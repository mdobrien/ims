package modules

import (
	"compress/gzip"
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nerdish/ims/pkg"
	"github.com/nerdish/ims/pkg/rpsl"
)

// WhoisARINModule processes ARIN WHOIS database dumps
type WhoisARINModule struct {
	storage *pkg.Storage
	baseURL string
	parser  *rpsl.Parser
}

// NewWhoisARIN creates a new ARIN WHOIS module
func NewWhoisARIN(storage *pkg.Storage) *WhoisARINModule {
	return &WhoisARINModule{
		storage: storage,
		baseURL: "https://ftp.arin.net/pub/rr",
		parser:  rpsl.NewParser(),
	}
}

func (m *WhoisARINModule) Name() string {
	return "whois-arin"
}

func (m *WhoisARINModule) Schedule() pkg.Schedule {
	return pkg.Schedule{
		Interval:   24 * time.Hour, // Daily updates
		Priority:   5,
		Timeout:    30 * time.Minute,
		MaxRetries: 3,
	}
}

func (m *WhoisARINModule) Process(ctx context.Context) error {
	url := fmt.Sprintf("%s/arin.db.gz", m.baseURL)

	log.Printf("[%s] Downloading: %s", m.Name(), url)

	// Download file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Decompress gzip
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip decompress: %w", err)
	}
	defer reader.Close()

	// Parse and store
	return m.parseAndStore(ctx, reader)
}

func (m *WhoisARINModule) parseAndStore(ctx context.Context, reader *gzip.Reader) error {
	const batchSize = 500

	// Parse objects from stream
	objects, errors := m.parser.ParseStream(reader)

	// Batch buffers
	inetnumBatch := make([]pkg.InetnumData, 0, batchSize)
	autnumBatch := make([]pkg.AutNumData, 0, batchSize)

	totalProcessed := int64(0)
	totalErrors := 0
	batchStart := time.Now()
	overallStart := time.Now()

	log.Printf("[%s] Starting to parse WHOIS objects (batch size: %d)...", m.Name(), batchSize)

	// Process objects
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errors:
			if ok && err != nil {
				totalErrors++
				if totalErrors%1000 == 0 {
					log.Printf("[%s] Parse errors: %d", m.Name(), totalErrors)
				}
			}
		case obj, ok := <-objects:
			if !ok {
				// Channel closed - flush remaining batches
				if len(inetnumBatch) > 0 {
					if err := m.storage.StoreInetnumBatch(ctx, inetnumBatch); err != nil {
						return fmt.Errorf("store inetnum batch: %w", err)
					}
					totalProcessed += int64(len(inetnumBatch))
				}
				if len(autnumBatch) > 0 {
					if err := m.storage.StoreAutNumBatch(ctx, autnumBatch); err != nil {
						return fmt.Errorf("store autnum batch: %w", err)
					}
					totalProcessed += int64(len(autnumBatch))
				}

				// Log completion
				totalDuration := time.Since(overallStart)
				rate := float64(totalProcessed) / totalDuration.Seconds()
				log.Printf("[%s] Completed: %d objects, %d errors", m.Name(), totalProcessed, totalErrors)
				log.Printf("[%s] Total time: %v (%.1f objects/sec)", m.Name(), totalDuration, rate)

				// Update module state
				errMsg := ""
				if totalErrors > 0 {
					errMsg = fmt.Sprintf("%d parse errors", totalErrors)
				}
				return m.storage.UpdateModuleState(ctx, m.Name(), true, totalProcessed, errMsg)
			}

			// Route object to appropriate batch
			// Note: ARIN primarily has route objects (90%), not inetnum
			switch obj.Type {
			case "inetnum", "inet6num":
				data, err := m.convertInetnum(obj)
				if err != nil {
					totalErrors++
					continue
				}
				inetnumBatch = append(inetnumBatch, data)

				// Flush batch if full
				if len(inetnumBatch) >= batchSize {
					if err := m.storage.StoreInetnumBatch(ctx, inetnumBatch); err != nil {
						return fmt.Errorf("store inetnum batch: %w", err)
					}
					totalProcessed += int64(len(inetnumBatch))
					inetnumBatch = inetnumBatch[:0]
				}

			case "aut-num":
				data, err := m.convertAutNum(obj)
				if err != nil {
					totalErrors++
					continue
				}
				autnumBatch = append(autnumBatch, data)

				// Flush batch if full
				if len(autnumBatch) >= batchSize {
					if err := m.storage.StoreAutNumBatch(ctx, autnumBatch); err != nil {
						return fmt.Errorf("store autnum batch: %w", err)
					}
					totalProcessed += int64(len(autnumBatch))
					autnumBatch = autnumBatch[:0]
				}
			}

			// Log progress
			if totalProcessed%5000 == 0 && totalProcessed > 0 {
				batchDuration := time.Since(batchStart)
				rate := float64(5000) / batchDuration.Seconds()
				log.Printf("[%s] Processed %d objects (%.1f obj/sec)",
					m.Name(), totalProcessed, rate)
				batchStart = time.Now()
			}
		}
	}
}

func (m *WhoisARINModule) convertInetnum(obj *rpsl.Object) (pkg.InetnumData, error) {
	// Extract range
	rangeStr := obj.PrimaryKey
	if rangeStr == "" {
		return pkg.InetnumData{}, fmt.Errorf("missing inetnum range")
	}

	// Parse IP range format: "start - end"
	var rangeStart, rangeEnd string
	if idx := strings.Index(rangeStr, " - "); idx > 0 {
		rangeStart = strings.TrimSpace(rangeStr[:idx])
		rangeEnd = strings.TrimSpace(rangeStr[idx+3:])
	} else {
		// Single IP or CIDR
		rangeStart = rangeStr
		rangeEnd = rangeStr
	}

	data := pkg.InetnumData{
		Source:       "arin-whois",
		RangeStart:   rangeStart,
		RangeEnd:     rangeEnd,
		Netname:      obj.GetAttribute("netname"),
		LastModified: time.Now(),
	}

	// Extract fields
	if data.Netname == "" {
		data.Netname = "ARIN-" + rangeStr
	}

	if status := obj.GetAttribute("status"); status != "" {
		data.Status = &status
	}
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// ARIN uses last-modified field (RFC3339 format)
	if lastMod := obj.GetAttribute("last-modified"); lastMod != "" {
		if t, err := time.Parse(time.RFC3339, lastMod); err == nil {
			data.LastModified = t
		}
	}

	return data, nil
}

func (m *WhoisARINModule) convertAutNum(obj *rpsl.Object) (pkg.AutNumData, error) {
	// Extract ASN
	asnStr := obj.PrimaryKey
	if asnStr == "" {
		return pkg.AutNumData{}, fmt.Errorf("missing aut-num")
	}

	// ARIN uses "AS1001" format - strip "AS" prefix
	asnStr = strings.TrimPrefix(asnStr, "AS")

	asn, err := strconv.ParseInt(asnStr, 10, 64)
	if err != nil {
		return pkg.AutNumData{}, fmt.Errorf("invalid asn %s: %w", asnStr, err)
	}

	// Get AS name
	asName := obj.GetAttribute("as-name")
	if asName == "" {
		asName = fmt.Sprintf("AS%d", asn)
	}

	data := pkg.AutNumData{
		Source:       "arin-whois",
		ASN:          asn,
		ASName:       asName,
		LastModified: time.Now(),
	}

	// Extract fields
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// ARIN uses last-modified field (RFC3339 format)
	if lastMod := obj.GetAttribute("last-modified"); lastMod != "" {
		if t, err := time.Parse(time.RFC3339, lastMod); err == nil {
			data.LastModified = t
		}
	}

	return data, nil
}
