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

// WhoisRIPEModule processes RIPE WHOIS database dumps
type WhoisRIPEModule struct {
	storage *pkg.Storage
	baseURL string
	parser  *rpsl.Parser
}

// NewWhoisRIPE creates a new RIPE WHOIS module
func NewWhoisRIPE(storage *pkg.Storage) *WhoisRIPEModule {
	return &WhoisRIPEModule{
		storage: storage,
		baseURL: "https://ftp.ripe.net/ripe/dbase",
		parser:  rpsl.NewParser(),
	}
}

func (m *WhoisRIPEModule) Name() string {
	return "whois-ripe"
}

func (m *WhoisRIPEModule) Schedule() pkg.Schedule {
	return pkg.Schedule{
		Interval:   24 * time.Hour, // Daily updates
		Priority:   9,
		Timeout:    120 * time.Minute,
		MaxRetries: 3,
	}
}

func (m *WhoisRIPEModule) Process(ctx context.Context) error {
	url := fmt.Sprintf("%s/ripe.db.gz", m.baseURL)

	log.Printf("[%s] Starting download: %s", m.Name(), url)

	// Download to temp file with retry logic
	tmpFile := "/tmp/ripe.db.gz"
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

func (m *WhoisRIPEModule) downloadToFile(ctx context.Context, url, filepath string) error {
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

// progressTracker wraps io.Reader to track download progress
type progressTracker struct {
	reader     io.Reader
	totalBytes *int64
	ticker     *time.Ticker
	moduleName string
	startTime  time.Time
	lastLog    time.Time
}

func (pt *progressTracker) Read(p []byte) (n int, err error) {
	n, err = pt.reader.Read(p)
	*pt.totalBytes += int64(n)

	// Check if we should log progress
	select {
	case <-pt.ticker.C:
		if time.Since(pt.lastLog) >= 10*time.Second {
			elapsed := time.Since(pt.startTime)
			mbDownloaded := float64(*pt.totalBytes) / (1024 * 1024)
			speed := mbDownloaded / elapsed.Seconds()
			log.Printf("[%s] Download progress: %.2f MB (%.2f MB/s)",
				pt.moduleName, mbDownloaded, speed)
			pt.lastLog = time.Now()
		}
	default:
		// Non-blocking, continue
	}

	return n, err
}

func (m *WhoisRIPEModule) parseAndStore(ctx context.Context, reader *gzip.Reader) error {
	const batchSize = 10000

	// Parse objects from stream
	objects, errors := m.parser.ParseStream(reader)

	// Batch buffers
	inetnumBatch := make([]pkg.InetnumData, 0, batchSize)
	autnumBatch := make([]pkg.AutNumData, 0, batchSize)
	routesBatch := make([]pkg.RouteData, 0, batchSize)
	orgBatch := make([]pkg.OrgData, 0, batchSize)
	objectsBatch := make([]pkg.WhoisObjectData, 0, batchSize)

	objectsReceived := int64(0)  // Total objects received from parser
	totalProcessed := int64(0)   // Total objects successfully stored
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
				if len(routesBatch) > 0 {
					if err := m.storage.StoreRoutesBatch(ctx, routesBatch); err != nil {
						return fmt.Errorf("store routes batch: %w", err)
					}
					totalProcessed += int64(len(routesBatch))
				}
				if len(orgBatch) > 0 {
					if err := m.storage.StoreOrgBatch(ctx, orgBatch); err != nil {
						return fmt.Errorf("store org batch: %w", err)
					}
					totalProcessed += int64(len(orgBatch))
				}
				if len(objectsBatch) > 0 {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, objectsBatch); err != nil {
						return fmt.Errorf("store objects batch: %w", err)
					}
					totalProcessed += int64(len(objectsBatch))
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

			// Increment counter for received objects
			objectsReceived++

			// Log progress every 10,000 objects
			if objectsReceived%10000 == 0 {
				elapsed := time.Since(overallStart)
				rate := float64(objectsReceived) / elapsed.Seconds()
				log.Printf("[%s] Progress: %d objects received, %d stored (%.1f obj/sec)",
					m.Name(), objectsReceived, totalProcessed, rate)
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
				routesBatch = append(routesBatch, data)

				// Flush batch if full
				if len(routesBatch) >= batchSize {
					if err := m.storage.StoreRoutesBatch(ctx, routesBatch); err != nil {
						return fmt.Errorf("store routes batch: %w", err)
					}
					totalProcessed += int64(len(routesBatch))
					routesBatch = routesBatch[:0]
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
				// All other object types go to generic objects table
				data := m.convertGenericObject(obj)
				objectsBatch = append(objectsBatch, data)

				// Flush batch if full
				if len(objectsBatch) >= batchSize {
					if err := m.storage.StoreWhoisObjectsBatch(ctx, objectsBatch); err != nil {
						return fmt.Errorf("store objects batch: %w", err)
					}
					totalProcessed += int64(len(objectsBatch))
					objectsBatch = objectsBatch[:0]
				}
			}
		}
	}
}

func (m *WhoisRIPEModule) convertInetnum(obj *rpsl.Object) (pkg.InetnumData, error) {
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
		Source:       "ripe-whois",
		RangeStart:   rangeStart,
		RangeEnd:     rangeEnd,
		Netname:      obj.GetAttribute("netname"),
		LastModified: time.Now(),
	}

	// Extract all available fields
	if data.Netname == "" {
		data.Netname = "RIPE-" + rangeStr
	}

	if status := obj.GetAttribute("status"); status != "" {
		data.Status = &status
	}
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}
	if orgID := obj.GetAttribute("org"); orgID != "" {
		data.OrgID = &orgID
	}

	// Extract array fields
	data.Descr = obj.GetAttributes("descr")
	data.AdminC = obj.GetAttributes("admin-c")
	data.TechC = obj.GetAttributes("tech-c")
	data.MntBy = obj.GetAttributes("mnt-by")

	// Extract dates
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

	// Store any remaining attributes in extra_attrs JSONB
	standardFields := map[string]bool{
		"inetnum": true, "inet6num": true, "netname": true, "status": true,
		"country": true, "org": true, "descr": true, "admin-c": true,
		"tech-c": true, "mnt-by": true, "created": true, "last-modified": true,
	}

	extraAttrs := make(map[string]interface{})
	for key, values := range obj.Attributes {
		if !standardFields[key] {
			if len(values) == 1 {
				extraAttrs[key] = values[0]
			} else if len(values) > 1 {
				extraAttrs[key] = values
			}
		}
	}
	if len(extraAttrs) > 0 {
		data.ExtraAttrs = extraAttrs
	}

	return data, nil
}

func (m *WhoisRIPEModule) convertAutNum(obj *rpsl.Object) (pkg.AutNumData, error) {
	// Extract ASN
	asnStr := obj.PrimaryKey
	if asnStr == "" {
		return pkg.AutNumData{}, fmt.Errorf("missing aut-num")
	}

	// Strip "AS" prefix if present (RIPE format is "AS12345")
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
		Source:       "ripe-whois",
		ASN:          asn,
		ASName:       asName,
		LastModified: time.Now(),
	}

	// Extract all available fields
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}
	if orgID := obj.GetAttribute("org"); orgID != "" {
		data.OrgID = &orgID
	}
	if status := obj.GetAttribute("status"); status != "" {
		data.Status = &status
	}

	// Extract array fields
	data.Descr = obj.GetAttributes("descr")
	data.AdminC = obj.GetAttributes("admin-c")
	data.TechC = obj.GetAttributes("tech-c")
	data.MntBy = obj.GetAttributes("mnt-by")

	// Extract policy fields (store as map with array value)
	if imports := obj.GetAttributes("import"); len(imports) > 0 {
		data.ImportPolicy = map[string]interface{}{"policies": imports}
	}
	if exports := obj.GetAttributes("export"); len(exports) > 0 {
		data.ExportPolicy = map[string]interface{}{"policies": exports}
	}

	// Extract dates
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

	// Store any remaining attributes in extra_attrs JSONB
	standardFields := map[string]bool{
		"aut-num": true, "as-name": true, "country": true, "org": true,
		"status": true, "descr": true, "admin-c": true, "tech-c": true,
		"mnt-by": true, "import": true, "export": true, "created": true,
		"last-modified": true,
	}

	extraAttrs := make(map[string]interface{})
	for key, values := range obj.Attributes {
		if !standardFields[key] {
			if len(values) == 1 {
				extraAttrs[key] = values[0]
			} else if len(values) > 1 {
				extraAttrs[key] = values
			}
		}
	}
	if len(extraAttrs) > 0 {
		data.ExtraAttrs = extraAttrs
	}

	return data, nil
}

func (m *WhoisRIPEModule) convertRoute(obj *rpsl.Object) (pkg.RouteData, error) {
	// Extract prefix (primary key for route objects)
	prefix := obj.PrimaryKey
	if prefix == "" {
		return pkg.RouteData{}, fmt.Errorf("missing route prefix")
	}

	data := pkg.RouteData{
		Source:       "ripe-whois",
		Prefix:       prefix,
		LastModified: time.Now(),
	}

	// Extract origin AS
	if origin := obj.GetAttribute("origin"); origin != "" {
		// Remove "AS" prefix if present
		origin = strings.TrimPrefix(origin, "AS")
		if asn, err := strconv.ParseInt(origin, 10, 64); err == nil {
			data.OriginASN = asn
		}
	}

	// Extract arrays
	data.Descr = obj.GetAttributes("descr")
	data.MntBy = obj.GetAttributes("mnt-by")
	data.MemberOf = obj.GetAttributes("member-of")

	// Extract dates
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

	// Store extra attributes
	data.ExtraAttrs = make(map[string]interface{})
	for key, values := range obj.Attributes {
		if key != "route" && key != "route6" && key != "origin" &&
		   key != "descr" && key != "mnt-by" && key != "member-of" &&
		   key != "created" && key != "last-modified" {
			if len(values) == 1 {
				data.ExtraAttrs[key] = values[0]
			} else if len(values) > 1 {
				data.ExtraAttrs[key] = values
			}
		}
	}

	return data, nil
}

func (m *WhoisRIPEModule) convertOrganisation(obj *rpsl.Object) (pkg.OrgData, error) {
	// Extract org ID (primary key)
	orgID := obj.PrimaryKey
	if orgID == "" {
		return pkg.OrgData{}, fmt.Errorf("missing organisation ID")
	}

	data := pkg.OrgData{
		Source:       "ripe-whois",
		OrgID:        orgID,
		LastModified: time.Now(),
	}

	// Extract name
	if orgName := obj.GetAttribute("org-name"); orgName != "" {
		data.OrgName = orgName
	}

	// Extract optional fields
	if orgType := obj.GetAttribute("org-type"); orgType != "" {
		data.OrgType = &orgType
	}
	if country := obj.GetAttribute("country"); country != "" {
		data.Country = &country
	}

	// Extract arrays
	data.Address = obj.GetAttributes("address")
	data.Email = obj.GetAttributes("e-mail")
	data.Phone = obj.GetAttributes("phone")
	data.AdminC = obj.GetAttributes("admin-c")
	data.TechC = obj.GetAttributes("tech-c")
	data.MntRef = obj.GetAttributes("mnt-ref")
	data.MntBy = obj.GetAttributes("mnt-by")

	// Extract dates
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

	// Store extra attributes
	data.ExtraAttrs = make(map[string]interface{})
	for key, values := range obj.Attributes {
		if key != "organisation" && key != "org-name" && key != "org-type" &&
		   key != "country" && key != "address" && key != "e-mail" &&
		   key != "phone" && key != "admin-c" && key != "tech-c" &&
		   key != "mnt-ref" && key != "mnt-by" && key != "created" &&
		   key != "last-modified" {
			if len(values) == 1 {
				data.ExtraAttrs[key] = values[0]
			} else if len(values) > 1 {
				data.ExtraAttrs[key] = values
			}
		}
	}

	return data, nil
}

func (m *WhoisRIPEModule) convertGenericObject(obj *rpsl.Object) pkg.WhoisObjectData {
	data := pkg.WhoisObjectData{
		Source:       "ripe-whois",
		ObjectType:   obj.Type,
		ObjectKey:    obj.PrimaryKey,
		Attributes:   make(map[string]interface{}),
		LastModified: time.Now(),
	}

	// Store all attributes as-is
	for key, values := range obj.Attributes {
		if len(values) == 1 {
			data.Attributes[key] = values[0]
		} else if len(values) > 1 {
			data.Attributes[key] = values
		}
	}

	// Try to extract last-modified if present
	if lastMod := obj.GetAttribute("last-modified"); lastMod != "" {
		if t, err := time.Parse(time.RFC3339, lastMod); err == nil {
			data.LastModified = t
		}
	}

	return data
}
