package modules

import (
	"bufio"
	"compress/bzip2"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/nerdish/ims/pkg"
)

// AtlasTracerouteModule processes RIPE Atlas traceroute daily dumps
type AtlasTracerouteModule struct {
	storage           *pkg.Storage
	baseURL           string
	downloadPath      string
	processFirstOnly  bool
	testDate          string // Optional: specific date for testing
}

// NewAtlasTraceroute creates a new Atlas traceroute module
func NewAtlasTraceroute(storage *pkg.Storage, baseURL, downloadPath string, processFirstOnly bool, testDate string) *AtlasTracerouteModule {
	return &AtlasTracerouteModule{
		storage:          storage,
		baseURL:          baseURL,
		downloadPath:     downloadPath,
		processFirstOnly: processFirstOnly,
		testDate:         testDate,
	}
}

func (m *AtlasTracerouteModule) Name() string {
	return "atlas-traceroute"
}

func (m *AtlasTracerouteModule) Schedule() pkg.Schedule {
	return pkg.Schedule{
		Interval:   24 * time.Hour, // Run daily
		Priority:   10,
		Timeout:    2 * time.Hour,
		MaxRetries: 3,
	}
}

func (m *AtlasTracerouteModule) Process(ctx context.Context) error {
	// Use test date if provided, otherwise use previous day
	var date string
	if m.testDate != "" {
		date = m.testDate
	} else {
		yesterday := time.Now().UTC().AddDate(0, 0, -1)
		date = yesterday.Format("2006-01-02")
	}

	log.Printf("[%s] Processing data for %s", m.Name(), date)

	// For skeleton: only process first file (00:00 hour)
	if m.processFirstOnly {
		return m.processFile(ctx, date, "0000")
	}

	// Process all 24 hourly files
	hours := []string{
		"0000", "0100", "0200", "0300", "0400", "0500",
		"0600", "0700", "0800", "0900", "1000", "1100",
		"1200", "1300", "1400", "1500", "1600", "1700",
		"1800", "1900", "2000", "2100", "2200", "2300",
	}

	totalProcessed := int64(0)
	totalErrors := 0

	for i, hour := range hours {
		log.Printf("[%s] === Processing file %d/24 (hour %s) ===", m.Name(), i+1, hour)

		processed, fileErrors, err := m.processFileWithStats(ctx, date, hour)
		if err != nil {
			log.Printf("[%s] Error processing hour %s: %v (continuing with next file)", m.Name(), hour, err)
			continue
		}

		totalProcessed += processed
		totalErrors += fileErrors
		log.Printf("[%s] Completed hour %s: %d traces (+%d errors). Running total: %d traces",
			m.Name(), hour, processed, fileErrors, totalProcessed)
	}

	log.Printf("[%s] === All 24 files completed ===", m.Name())
	log.Printf("[%s] Grand total: %d traceroutes, %d errors", m.Name(), totalProcessed, totalErrors)

	// Update final module state
	errMsg := ""
	if totalErrors > 0 {
		errMsg = fmt.Sprintf("%d total errors across all files", totalErrors)
	}
	return m.storage.UpdateModuleState(ctx, m.Name(), true, totalProcessed, errMsg)
}

func (m *AtlasTracerouteModule) processFile(ctx context.Context, date, hour string) error {
	_, _, err := m.processFileWithStats(ctx, date, hour)
	return err
}

func (m *AtlasTracerouteModule) processFileWithStats(ctx context.Context, date, hour string) (int64, int, error) {
	// Build URL: https://data-store.ripe.net/datasets/atlas-daily-dumps/2025-10-26/traceroute-2025-10-26T0000.bz2
	url := fmt.Sprintf("%s/%s/traceroute-%sT%s.bz2", m.baseURL, date, date, hour)

	log.Printf("[%s] Downloading: %s", m.Name(), url)

	// Download file
	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Decompress bz2
	reader := bzip2.NewReader(resp.Body)

	// Parse JSONL (newline-delimited JSON)
	return m.parseAndStore(ctx, reader, date, hour)
}

func (m *AtlasTracerouteModule) parseAndStore(ctx context.Context, reader io.Reader, date, hour string) (int64, int, error) {
	scanner := bufio.NewScanner(reader)

	// Increase buffer size for large lines
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	count := int64(0)
	errors := 0
	const batchSize = 500      // Batch size for database inserts

	// Timing for batches
	batchStart := time.Now()
	overallStart := time.Now()

	log.Printf("[%s] Starting to process file (streaming decompression, batch size: %d)...", m.Name(), batchSize)

	// Batch buffer
	batch := make([]pkg.TracerouteData, 0, batchSize)

	for scanner.Scan() {

		select {
		case <-ctx.Done():
			return count, errors, ctx.Err()
		default:
		}

		var atlasData AtlasTraceroute
		if err := json.Unmarshal(scanner.Bytes(), &atlasData); err != nil {
			errors++
			if errors%1000 == 0 {
				log.Printf("[%s] Parse errors: %d", m.Name(), errors)
			}
			continue
		}

		// Convert to TracerouteData
		traceData, err := m.convertAtlasTraceroute(atlasData)
		if err != nil {
			errors++
			continue
		}

		// Add to batch
		batch = append(batch, traceData)

		// Flush batch when full
		if len(batch) >= batchSize {
			if err := m.storage.StoreTracerouteBatch(ctx, batch); err != nil {
				log.Printf("[%s] Batch insert error: %v", m.Name(), err)
				errors += len(batch)
			} else {
				count += int64(len(batch))
			}
			batch = batch[:0] // Clear batch

			if count%1000 == 0 {
				batchDuration := time.Since(batchStart)
				batchRate := float64(1000) / batchDuration.Seconds()
				log.Printf("[%s] Processed %d traceroutes (batch: %v, rate: %.1f traces/sec)",
					m.Name(), count, batchDuration, batchRate)
				batchStart = time.Now()
			}
		}
	}

	// Flush remaining batch
	if len(batch) > 0 {
		if err := m.storage.StoreTracerouteBatch(ctx, batch); err != nil {
			log.Printf("[%s] Final batch insert error: %v", m.Name(), err)
			errors += len(batch)
		} else {
			count += int64(len(batch))
		}
	}

	// Check for scanner errors (but EOF is normal at end of file)
	if err := scanner.Err(); err != nil {
		// Log as warning but don't fail if we processed some data
		if count > 0 {
			log.Printf("[%s] Warning: scanner error after processing %d traces: %v", m.Name(), count, err)
		} else {
			return 0, 0, fmt.Errorf("scanner error: %w", err)
		}
	}

	totalDuration := time.Since(overallStart)
	overallRate := float64(count) / totalDuration.Seconds()

	log.Printf("[%s] File completed: %d traceroutes, %d errors", m.Name(), count, errors)
	log.Printf("[%s] File time: %v (%.1f traces/sec)", m.Name(), totalDuration, overallRate)

	return count, errors, nil
}

func (m *AtlasTracerouteModule) convertAtlasTraceroute(atlas AtlasTraceroute) (pkg.TracerouteData, error) {
	// Handle missing src_addr/dst_addr (1% of data)
	if atlas.SrcAddr == "" || atlas.DstAddr == "" {
		return pkg.TracerouteData{}, fmt.Errorf("missing src_addr or dst_addr")
	}

	// Generate source measurement ID
	sourceID := fmt.Sprintf("msm_%d_prb_%d", atlas.MsmID, atlas.PrbID)
	probeID := fmt.Sprintf("%d", atlas.PrbID)
	timestamp := time.Unix(atlas.Timestamp, 0)

	// Convert Atlas hops to our format
	hops := make([]pkg.TracerouteHop, 0, len(atlas.Result))
	for _, atlasHop := range atlas.Result {
		hop := m.convertAtlasHop(atlasHop)
		hops = append(hops, hop)
	}

	return pkg.TracerouteData{
		Source:              "atlas-traceroute",
		SourceMeasurementID: sourceID,
		ProbeID:             probeID,
		Timestamp:           timestamp,
		SrcIP:               atlas.SrcAddr,
		TargetIP:            atlas.DstAddr,
		Proto:               atlas.Proto,
		Hops:                hops,
	}, nil
}

func (m *AtlasTracerouteModule) convertAtlasHop(atlasHop AtlasHop) pkg.TracerouteHop {
	hop := pkg.TracerouteHop{}

	// Handle no responses or timeout
	if len(atlasHop.Result) == 0 {
		hop.Timeout = true
		return hop
	}

	// Check for timeout marker
	firstReply := atlasHop.Result[0]
	if firstReply.X == "*" {
		hop.Timeout = true
		return hop
	}

	// Process successful responses
	if firstReply.From != "" {
		hop.HopDstIP = &firstReply.From
	}

	// Average RTT across all probe attempts
	totalRTT := 0.0
	validRTTs := 0
	var ttl *int
	var size *int

	for _, reply := range atlasHop.Result {
		if reply.RTT > 0 {
			totalRTT += reply.RTT
			validRTTs++
		}
		if reply.TTL > 0 && ttl == nil {
			ttl = &reply.TTL
		}
		if reply.Size > 0 && size == nil {
			size = &reply.Size
		}
	}

	if validRTTs > 0 {
		avgRTT := totalRTT / float64(validRTTs)
		hop.RTTms = &avgRTT
	}

	hop.TTL = ttl
	hop.ResponseSize = size

	// Store error code if present
	if firstReply.Err != "" {
		hop.ErrCode = &firstReply.Err
	}

	// TODO: Lookup ASN for hop IP
	// For skeleton, leave ASN as NULL

	return hop
}

// AtlasTraceroute represents the Atlas JSON format
type AtlasTraceroute struct {
	MsmID     int64      `json:"msm_id"`
	PrbID     int        `json:"prb_id"`
	Timestamp int64      `json:"timestamp"`
	Proto     string     `json:"proto"`
	AF        int        `json:"af"`
	DstAddr   string     `json:"dst_addr"`
	SrcAddr   string     `json:"src_addr"`
	Result    []AtlasHop `json:"result"`
}

type AtlasHop struct {
	Hop    int          `json:"hop"`
	Result []AtlasReply `json:"result"`
}

type AtlasReply struct {
	From string  `json:"from"`
	RTT  float64 `json:"rtt"`
	TTL  int     `json:"ttl"`
	Size int     `json:"size"`
	X    string  `json:"x"`   // "*" for timeout
	Err  string  `json:"err"` // Error code
}
