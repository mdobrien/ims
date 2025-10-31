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

// WhoisLACNICModule processes LACNIC WHOIS database dumps
type WhoisLACNICModule struct {
	storage *pkg.Storage
	baseURL string
	parser  *rpsl.Parser
}

// NewWhoisLACNIC creates a new LACNIC WHOIS module
func NewWhoisLACNIC(storage *pkg.Storage) *WhoisLACNICModule {
	return &WhoisLACNICModule{
		storage: storage,
		baseURL: "https://ftp.lacnic.net/lacnic/dbase",
		parser:  rpsl.NewParser(),
	}
}

func (m *WhoisLACNICModule) Name() string {
	return "whois-lacnic"
}

func (m *WhoisLACNICModule) Schedule() pkg.Schedule {
	return pkg.Schedule{
		Interval:   24 * time.Hour, // Daily updates
		Priority:   6,
		Timeout:    30 * time.Minute,
		MaxRetries: 3,
	}
}

func (m *WhoisLACNICModule) Process(ctx context.Context) error {
	url := fmt.Sprintf("%s/lacnic.db.gz", m.baseURL)

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

func (m *WhoisLACNICModule) parseAndStore(ctx context.Context, reader *gzip.Reader) error {
	const batchSize = 500

	// Parse objects from stream
	objects, errors := m.parser.ParseStream(reader)

	// Batch buffers
	inetnumBatch := make([]pkg.InetnumData, 0, batchSize)
	autnumBatch := make([]pkg.AutNumData, 0, batchSize)
	routeBatch := make([]pkg.RouteData, 0, batchSize)
	orgBatch := make([]pkg.OrgData, 0, batchSize)
	genericBatch := make([]pkg.WhoisObjectData, 0, batchSize)

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
				if len(routeBatch) > 0 {
					if err := m.storage.StoreRoutesBatch(ctx, routeBatch); err != nil {
						return fmt.Errorf("store routes batch: %w", err)
					}
					totalProcessed += int64(len(routeBatch))
				}
				if len(orgBatch) > 0 {
					if err := m.storage.StoreOrgBatch(ctx, orgBatch); err != nil {
						return fmt.Errorf("store org batch: %w", err)
					}
					totalProcessed += int64(len(orgBatch))
				}
				if len(genericBatch) > 0 {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, genericBatch); err != nil {
						return fmt.Errorf("store generic objects batch: %w", err)
					}
					totalProcessed += int64(len(genericBatch))
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
						return fmt.Errorf("store routes batch: %w", err)
					}
					totalProcessed += int64(len(routeBatch))
					routeBatch = routeBatch[:0]
				}

			case "organisation":
				data, err := m.convertOrganisation(obj)
				if err != nil {
					totalErrors++
					continue
				}
				orgBatch = append(orgBatch, data)

				// Flush batch if full
				if len(orgBatch) >= batchSize {
					if err := m.storage.StoreOrgBatch(ctx, orgBatch); err != nil {
						return fmt.Errorf("store org batch: %w", err)
					}
					totalProcessed += int64(len(orgBatch))
					orgBatch = orgBatch[:0]
				}

			default:
				// All other object types go to generic whois_objects table
				data := m.convertGenericObject(obj)
				genericBatch = append(genericBatch, data)

				// Flush batch if full
				if len(genericBatch) >= batchSize {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, genericBatch); err != nil {
						return fmt.Errorf("store generic batch: %w", err)
					}
					totalProcessed += int64(len(genericBatch))
					genericBatch = genericBatch[:0]
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

func (m *WhoisLACNICModule) convertInetnum(obj *rpsl.Object) (pkg.InetnumData, error) {
	// Extract range
	rangeStr := obj.PrimaryKey
	if rangeStr == "" {
		return pkg.InetnumData{}, fmt.Errorf("missing inetnum range")
	}

	// LACNIC format is just CIDR (e.g., "5.183.80/22") not range
	// We need to convert to range format for storage
	// For now, use the value as both start and end (TODO: proper CIDR parsing)
	data := pkg.InetnumData{
		Source:       "lacnic-whois",
		RangeStart:   rangeStr,
		RangeEnd:     rangeStr,
		Netname:      "LACNIC-" + rangeStr, // LACNIC doesn't always have netname
		LastModified: time.Now(),           // LACNIC uses "changed" field
	}

	// Extract fields
	if status := obj.GetAttribute("status"); status != "" {
		data.Status = &status
	}
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// Changed date as last_modified
	if changed := obj.GetAttribute("changed"); changed != "" {
		if t, err := parseDate(changed); err == nil {
			data.LastModified = t
		}
	}
	if created := obj.GetAttribute("created"); created != "" {
		if t, err := parseDate(created); err == nil {
			data.Created = &t
		}
	}

	return data, nil
}

func (m *WhoisLACNICModule) convertAutNum(obj *rpsl.Object) (pkg.AutNumData, error) {
	// Extract ASN
	asnStr := obj.PrimaryKey
	if asnStr == "" {
		return pkg.AutNumData{}, fmt.Errorf("missing aut-num")
	}

	asn, err := strconv.ParseInt(asnStr, 10, 64)
	if err != nil {
		return pkg.AutNumData{}, fmt.Errorf("invalid asn %s: %w", asnStr, err)
	}

	data := pkg.AutNumData{
		Source:       "lacnic-whois",
		ASN:          asn,
		ASName:       fmt.Sprintf("AS%d", asn), // LACNIC doesn't have as-name
		LastModified: time.Now(),
	}

	// Extract fields
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// Changed date
	if changed := obj.GetAttribute("changed"); changed != "" {
		if t, err := parseDate(changed); err == nil {
			data.LastModified = t
		}
	}
	if created := obj.GetAttribute("created"); created != "" {
		if t, err := parseDate(created); err == nil {
			data.Created = &t
		}
	}

	return data, nil
}

func (m *WhoisLACNICModule) convertRoute(obj *rpsl.Object) (pkg.RouteData, error) {
	// Extract prefix and origin
	prefix := obj.PrimaryKey
	if prefix == "" {
		return pkg.RouteData{}, fmt.Errorf("missing route prefix")
	}

	originStr := obj.GetAttribute("origin")
	if originStr == "" {
		return pkg.RouteData{}, fmt.Errorf("missing origin ASN")
	}

	// Parse ASN (may have AS prefix)
	originStr = strings.TrimPrefix(originStr, "AS")
	origin, err := strconv.ParseInt(originStr, 10, 64)
	if err != nil {
		return pkg.RouteData{}, fmt.Errorf("invalid origin %s: %w", originStr, err)
	}

	data := pkg.RouteData{
		Source:       "lacnic-whois",
		Prefix:       prefix,
		OriginASN:    origin,
		LastModified: time.Now(),
	}

	// Extract fields
	if changed := obj.GetAttribute("changed"); changed != "" {
		if t, err := parseDate(changed); err == nil {
			data.LastModified = t
		}
	}
	if created := obj.GetAttribute("created"); created != "" {
		if t, err := parseDate(created); err == nil {
			data.Created = &t
		}
	}

	return data, nil
}

func (m *WhoisLACNICModule) convertOrganisation(obj *rpsl.Object) (pkg.OrgData, error) {
	orgID := obj.PrimaryKey
	if orgID == "" {
		return pkg.OrgData{}, fmt.Errorf("missing organisation ID")
	}

	orgName := obj.GetAttribute("org-name")
	if orgName == "" {
		return pkg.OrgData{}, fmt.Errorf("missing org-name")
	}

	data := pkg.OrgData{
		Source:       "lacnic-whois",
		OrgID:        orgID,
		OrgName:      orgName,
		LastModified: time.Now(),
	}

	// Extract fields
	if orgType := obj.GetAttribute("org-type"); orgType != "" {
		data.OrgType = &orgType
	}
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// Changed date
	if changed := obj.GetAttribute("changed"); changed != "" {
		if t, err := parseDate(changed); err == nil {
			data.LastModified = t
		}
	}
	if created := obj.GetAttribute("created"); created != "" {
		if t, err := parseDate(created); err == nil {
			data.Created = &t
		}
	}

	return data, nil
}

func (m *WhoisLACNICModule) convertGenericObject(obj *rpsl.Object) pkg.WhoisObjectData {
	// Store all attributes as JSONB
	attrs := make(map[string]interface{})
	for key, values := range obj.Attributes {
		if len(values) == 1 {
			attrs[key] = values[0]
		} else {
			attrs[key] = values
		}
	}

	data := pkg.WhoisObjectData{
		Source:       "lacnic-whois",
		ObjectType:   obj.Type,
		ObjectKey:    obj.PrimaryKey,
		Attributes:   attrs,
		LastModified: time.Now(),
	}

	// Extract last-modified if available
	if changed := obj.GetAttribute("changed"); changed != "" {
		if t, err := parseDate(changed); err == nil {
			data.LastModified = t
		}
	}

	return data
}

// parseDate handles LACNIC date format (YYYY-MM-DD)
func parseDate(dateStr string) (time.Time, error) {
	return time.Parse("2006-01-02", dateStr)
}
