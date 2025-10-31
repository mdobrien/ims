package modules

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

	log.Printf("[%s] Starting download: %s", m.Name(), url)

	// Download to temp file with retry logic
	tmpFile := "/tmp/arin.db.gz"
	var lastErr error
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("[%s] Retry attempt %d/%d", m.Name(), attempt, maxRetries)
			time.Sleep(10 * time.Second) // Wait before retry
		}

		err := m.downloadToFile(ctx, url, tmpFile)
		if err == nil {
			break // Success
		}
		lastErr = err
		log.Printf("[%s] Download attempt %d failed: %v", m.Name(), attempt, err)

		if attempt == maxRetries {
			return fmt.Errorf("download failed after %d attempts: %w", maxRetries, lastErr)
		}
	}

	// Ensure temp file is cleaned up
	defer func() {
		if err := os.Remove(tmpFile); err != nil {
			log.Printf("[%s] Warning: failed to remove temp file: %v", m.Name(), err)
		}
	}()

	// Open the downloaded file
	file, err := os.Open(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to open downloaded file: %w", err)
	}
	defer file.Close()

	// Get file info for logging
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	log.Printf("[%s] Processing file: %s (size: %.2f MB)",
		m.Name(), tmpFile, float64(fileInfo.Size())/(1024*1024))

	// Decompress gzip
	reader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("gzip decompress: %w", err)
	}
	defer reader.Close()

	// Parse and store
	return m.parseAndStore(ctx, reader)
}

func (m *WhoisARINModule) downloadToFile(ctx context.Context, url, filepath string) error {
	// Create HTTP client with extended timeout
	client := &http.Client{
		Timeout: 30 * time.Minute, // 30 minutes for large file download
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	// Log response headers
	contentLength := resp.Header.Get("Content-Length")
	if contentLength != "" {
		log.Printf("[%s] Content-Length: %s bytes", m.Name(), contentLength)
	}

	// Create temp file
	tempFile, err := os.Create(filepath + ".tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer tempFile.Close()

	// Download with progress tracking
	startTime := time.Now()
	var totalBytes int64
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Create a reader that tracks progress
	progressReader := &progressTracker{
		reader:     resp.Body,
		totalBytes: &totalBytes,
		ticker:     ticker,
		moduleName: m.Name(),
		startTime:  startTime,
	}

	// Copy to file
	written, err := io.Copy(tempFile, progressReader)
	if err != nil {
		os.Remove(filepath + ".tmp")
		return fmt.Errorf("download copy: %w", err)
	}

	// Sync to disk
	if err := tempFile.Sync(); err != nil {
		os.Remove(filepath + ".tmp")
		return fmt.Errorf("sync file: %w", err)
	}

	// Rename temp file to final name
	if err := os.Rename(filepath+".tmp", filepath); err != nil {
		os.Remove(filepath + ".tmp")
		return fmt.Errorf("rename file: %w", err)
	}

	duration := time.Since(startTime)
	log.Printf("[%s] Download complete: %.2f MB in %v (%.2f MB/s)",
		m.Name(), float64(written)/(1024*1024), duration,
		float64(written)/(1024*1024)/duration.Seconds())

	return nil
}

func (m *WhoisARINModule) parseAndStore(ctx context.Context, reader *gzip.Reader) error {
	const batchSize = 10000

	// Parse objects from stream
	objects, errors := m.parser.ParseStream(reader)

	// Batch buffers
	inetnumBatch := make([]pkg.InetnumData, 0, batchSize)
	autnumBatch := make([]pkg.AutNumData, 0, batchSize)
	routeBatch := make([]pkg.RouteData, 0, batchSize)
	whoisObjectBatch := make([]pkg.WhoisObjectData, 0, batchSize)

	objectsReceived := int64(0)
	totalProcessed := int64(0)
	totalErrors := 0
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
				if len(routeBatch) > 0 {
					if err := m.storage.StoreRoutesBatch(ctx, routeBatch); err != nil {
						return fmt.Errorf("store route batch: %w", err)
					}
					totalProcessed += int64(len(routeBatch))
				}
				if len(whoisObjectBatch) > 0 {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, whoisObjectBatch); err != nil {
						return fmt.Errorf("store whois object batch: %w", err)
					}
					totalProcessed += int64(len(whoisObjectBatch))
				}

				// Log completion
				totalDuration := time.Since(overallStart)
				rate := float64(objectsReceived) / totalDuration.Seconds()
				log.Printf("[%s] Parsing complete: %d objects received, %d stored, %d errors",
					m.Name(), objectsReceived, totalProcessed, totalErrors)
				log.Printf("[%s] Total time: %v (%.1f objects/sec)", m.Name(), totalDuration, rate)

				// Update module state
				errMsg := ""
				if totalErrors > 0 {
					errMsg = fmt.Sprintf("%d parse errors", totalErrors)
				}
				return m.storage.UpdateModuleState(ctx, m.Name(), true, totalProcessed, errMsg)
			}

			// Track objects received
			objectsReceived++

			// Log progress every 10,000 objects
			if objectsReceived%10000 == 0 {
				elapsed := time.Since(overallStart)
				rate := float64(objectsReceived) / elapsed.Seconds()
				log.Printf("[%s] Progress: %d objects received, %d stored (%.1f obj/sec)",
					m.Name(), objectsReceived, totalProcessed, rate)
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

			case "route", "route6":
				data, err := m.convertRoute(obj)
				if err != nil {
					totalErrors++
					continue
				}
				routeBatch = append(routeBatch, data)

				// Flush batch if full
				if len(routeBatch) >= batchSize {
					if err := m.storage.StoreRoutesBatch(ctx, routeBatch); err != nil {
						return fmt.Errorf("store route batch: %w", err)
					}
					totalProcessed += int64(len(routeBatch))
					routeBatch = routeBatch[:0]
				}

			default:
				// Handle other object types (as-set, route-set, etc.)
				// Convert attributes to map for storage
				attrs := make(map[string]interface{})
				for key, values := range obj.Attributes {
					if len(values) == 1 {
						attrs[key] = values[0]
					} else {
						attrs[key] = values
					}
				}

				genericObj := pkg.WhoisObjectData{
					Source:       "arin-whois",
					ObjectType:   obj.Type,
					ObjectKey:    obj.PrimaryKey,
					Attributes:   attrs,
					LastModified: time.Now(),
				}

				// Try to extract last-modified if present
				if lastMod := obj.GetAttribute("last-modified"); lastMod != "" {
					if t, err := time.Parse(time.RFC3339, lastMod); err == nil {
						genericObj.LastModified = t
					}
				}

				whoisObjectBatch = append(whoisObjectBatch, genericObj)

				// Flush batch if full
				if len(whoisObjectBatch) >= batchSize {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, whoisObjectBatch); err != nil {
						return fmt.Errorf("store whois object batch: %w", err)
					}
					totalProcessed += int64(len(whoisObjectBatch))
					whoisObjectBatch = whoisObjectBatch[:0]
				}
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

func (m *WhoisARINModule) convertRoute(obj *rpsl.Object) (pkg.RouteData, error) {
	// Extract route prefix
	prefix := obj.PrimaryKey
	if prefix == "" {
		return pkg.RouteData{}, fmt.Errorf("missing route prefix")
	}

	// Extract origin AS
	originStr := obj.GetAttribute("origin")
	if originStr == "" {
		return pkg.RouteData{}, fmt.Errorf("missing origin AS")
	}

	// Strip "AS" prefix if present
	originStr = strings.TrimPrefix(originStr, "AS")
	origin, err := strconv.ParseInt(originStr, 10, 64)
	if err != nil {
		return pkg.RouteData{}, fmt.Errorf("invalid origin AS %s: %w", originStr, err)
	}

	data := pkg.RouteData{
		Source:       "arin-whois",
		Prefix:       prefix,
		OriginASN:    origin,
		LastModified: time.Now(),
	}

	// Extract optional multi-value fields
	if descrs := obj.GetAttributes("descr"); len(descrs) > 0 {
		data.Descr = descrs
	}
	if mntBy := obj.GetAttributes("mnt-by"); len(mntBy) > 0 {
		data.MntBy = mntBy
	}
	if memberOf := obj.GetAttributes("member-of"); len(memberOf) > 0 {
		data.MemberOf = memberOf
	}

	// Parse timestamps
	if created := obj.GetAttribute("created"); created != "" {
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			data.Created = &t
		}
	}
	if lastMod := obj.GetAttribute("last-modified"); lastMod != "" {
		if t, err := time.Parse(time.RFC3339, lastMod); err == nil {
			data.LastModified = t
		}
	}

	return data, nil
}
