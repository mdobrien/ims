# Scalable Traceroute Schema - Hybrid Design

## Design Philosophy

**Scale for tens of millions of traceroutes with production-ready reliability:**
- One row per hop (not per traceroute)
- Hybrid ID approach: auto-increment + natural source IDs
- Idempotent inserts (crash recovery safe)
- No coordination needed between processes
- Can safely run multiple module instances

## Schema Design

```
┌────────────────────────────────────────────────────────────────────────┐
│                        traceroute_hops                                 │
├────────────────────────────────────────────────────────────────────────┤
│ id (bigserial)              ← Auto-increment (fast internal queries)  │
│ timestamp (timestamptz)     ← Partition key                           │
│ source (text)               ← 'atlas-traceroute', 'scamper-sg', etc.  │
│ source_measurement_id (text)← Natural ID from source (idempotency)    │
│ hop_num (int)               ← Hop sequence (1, 2, 3...)               │
│ hop_src_ip (inet)           ← This hop's source IP                    │
│ hop_dst_ip (inet)           ← This hop's destination IP               │
│ target_ip (inet)            ← Final traceroute target                 │
│ rtt_ms (real)               ← Round trip time                         │
│ asn (int)                   ← ASN of hop_dst_ip                       │
│ timeout (bool)              ← Did this hop timeout?                   │
└────────────────────────────────────────────────────────────────────────┘

UNIQUE constraint on (source, source_measurement_id, timestamp, hop_num)
```

## SQL Schema

```sql
CREATE TABLE traceroute_hops (
    id BIGSERIAL,                      -- Auto-increment for fast queries
    timestamp TIMESTAMPTZ NOT NULL,     -- When this traceroute ran

    -- Natural identifiers (enables idempotency)
    source TEXT NOT NULL,               -- 'atlas-traceroute', 'scamper-vps1', etc.
    source_measurement_id TEXT NOT NULL,-- Source's native ID
    probe_id TEXT,                      -- Probe identifier (Atlas probe ID, VPS hostname, etc.)

    -- Hop details
    hop_num INT NOT NULL,               -- 1, 2, 3, 4...
    hop_src_ip INET NOT NULL,           -- Previous hop or source
    hop_dst_ip INET,                    -- This hop's IP (NULL if timeout)
    target_ip INET NOT NULL,            -- Final destination of traceroute

    -- Measurement details
    proto TEXT NOT NULL,                -- Protocol: 'ICMP', 'UDP', 'TCP'
    rtt_ms REAL,                        -- Round trip time in milliseconds
    ttl INT,                            -- TTL value in response packet
    response_size INT,                  -- Response packet size (bytes)
    asn INT,                            -- ASN of hop_dst_ip

    -- Error handling
    timeout BOOLEAN DEFAULT false,      -- Did this hop timeout?
    err_code TEXT,                      -- Error code: 'H' (host unreach), 'N' (net unreach), etc.

    -- Flexible storage for source-specific data
    extra_data JSONB,                   -- ICMP extensions, itos, ittl, flags, etc.

    PRIMARY KEY (timestamp, id),
    -- Prevent duplicate ingestion (idempotency!)
    UNIQUE (source, source_measurement_id, timestamp, hop_num)
);

-- Convert to TimescaleDB hypertable (partitions by timestamp automatically)
SELECT create_hypertable('traceroute_hops', 'timestamp',
    chunk_time_interval => INTERVAL '1 day');

-- Indexes for common queries
CREATE INDEX idx_hops_target ON traceroute_hops(target_ip, timestamp DESC);
CREATE INDEX idx_hops_dst_ip ON traceroute_hops(hop_dst_ip, timestamp DESC);
CREATE INDEX idx_hops_source ON traceroute_hops(source, timestamp DESC);
CREATE INDEX idx_hops_source_measurement ON traceroute_hops(source, source_measurement_id);
CREATE INDEX idx_hops_proto ON traceroute_hops(proto);  -- Filter by protocol
CREATE INDEX idx_hops_probe ON traceroute_hops(probe_id) WHERE probe_id IS NOT NULL;
```

## Source Measurement ID Generation

Different sources generate IDs differently:

### RIPE Atlas
```go
// Use Atlas's measurement ID + probe ID
sourceID := fmt.Sprintf("msm_%d_prb_%d",
    measurement.MeasurementID,  // e.g., 123456
    measurement.ProbeID)        // e.g., 5678

// Result: "msm_123456_prb_5678"
```

### Scamper from VPS
```go
// Use hostname + timestamp + target
sourceID := fmt.Sprintf("vps_%s_%d_%s",
    hostname,                   // e.g., "singapore-01"
    timestamp.Unix(),           // e.g., 1730217600
    targetIP)                   // e.g., "8.8.8.8"

// Result: "vps_singapore-01_1730217600_8.8.8.8"
```

### Custom Measurement Tool
```go
// Use UUID or similar
sourceID := uuid.New().String()

// Result: "550e8400-e29b-41d4-a716-446655440000"
```

## Example Data

A traceroute from 192.168.1.1 → 8.8.8.8 via RIPE Atlas:

```sql
id  | timestamp           | source             | source_measurement_id  | hop | hop_src_ip  | hop_dst_ip | target_ip | rtt_ms
1   | 2025-10-29 10:00:00 | atlas-traceroute   | msm_12345_prb_5678    | 1   | 192.168.1.1 | 10.0.0.1   | 8.8.8.8   | 1.2
2   | 2025-10-29 10:00:00 | atlas-traceroute   | msm_12345_prb_5678    | 2   | 10.0.0.1    | 8.8.4.4    | 8.8.8.8   | 5.1
3   | 2025-10-29 10:00:00 | atlas-traceroute   | msm_12345_prb_5678    | 3   | 8.8.4.4     | 8.8.8.8    | 8.8.8.8   | 10.5
```

## Insert Example (Idempotent!)

```sql
-- Insert with automatic deduplication
INSERT INTO traceroute_hops
    (timestamp, source, source_measurement_id, hop_num,
     hop_src_ip, hop_dst_ip, target_ip, rtt_ms, asn)
VALUES
    (NOW(), 'atlas-traceroute', 'msm_12345_prb_5678', 1,
     '192.168.1.1', '10.0.0.1', '8.8.8.8', 1.2, 64512),
    (NOW(), 'atlas-traceroute', 'msm_12345_prb_5678', 2,
     '10.0.0.1', '8.8.4.4', '8.8.8.8', 5.1, 15169),
    (NOW(), 'atlas-traceroute', 'msm_12345_prb_5678', 3,
     '8.8.4.4', '8.8.8.8', '8.8.8.8', 10.5, 15169)
ON CONFLICT (source, source_measurement_id, timestamp, hop_num)
DO NOTHING;  -- Skip duplicates silently

-- Or update if you want to refresh data:
-- DO UPDATE SET rtt_ms = EXCLUDED.rtt_ms, asn = EXCLUDED.asn;
```

## Go Implementation

```go
type TracerouteHop struct {
    HopNum       int
    HopSrcIP     string
    HopDstIP     string
    RTTms        float64
    ASN          *int
    Timeout      bool
}

// Idempotent storage - safe to call multiple times
func StoreTraceroute(db *sql.DB, source, sourceMeasurementID string,
                     timestamp time.Time, srcIP, targetIP string,
                     hops []TracerouteHop) error {

    // Prepare statement for batch insert
    stmt, err := db.Prepare(`
        INSERT INTO traceroute_hops
            (timestamp, source, source_measurement_id, hop_num,
             hop_src_ip, hop_dst_ip, target_ip, rtt_ms, asn, timeout)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source, source_measurement_id, timestamp, hop_num)
        DO NOTHING
    `)
    if err != nil {
        return err
    }
    defer stmt.Close()

    prevIP := srcIP
    for i, hop := range hops {
        _, err := stmt.Exec(
            timestamp,
            source,
            sourceMeasurementID,
            i+1,              // hop_num
            prevIP,           // hop_src_ip
            hop.HopDstIP,     // hop_dst_ip
            targetIP,
            hop.RTTms,
            hop.ASN,
            hop.Timeout,
        )
        if err != nil {
            return err
        }

        if hop.HopDstIP != "" {
            prevIP = hop.HopDstIP
        }
    }

    return nil
}

// Query by source measurement ID
func GetTraceroute(db *sql.DB, source, sourceMeasurementID string,
                   timestamp time.Time) ([]TracerouteHop, error) {
    rows, err := db.Query(`
        SELECT hop_num, hop_src_ip, hop_dst_ip, target_ip,
               rtt_ms, asn, timeout
        FROM traceroute_hops
        WHERE source = $1
          AND source_measurement_id = $2
          AND timestamp = $3
        ORDER BY hop_num
    `, source, sourceMeasurementID, timestamp)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var hops []TracerouteHop
    for rows.Next() {
        var hop TracerouteHop
        var targetIP string
        err := rows.Scan(&hop.HopNum, &hop.HopSrcIP, &hop.HopDstIP,
                        &targetIP, &hop.RTTms, &hop.ASN, &hop.Timeout)
        if err != nil {
            return nil, err
        }
        hops = append(hops, hop)
    }

    return hops, rows.Err()
}
```

## RIPE Atlas Data Format

### Atlas JSON Structure (from analysis)

```json
{
  "msm_id": 123456,
  "prb_id": 5678,
  "timestamp": 1730217600,
  "endtime": 1730217615,
  "type": "traceroute",
  "proto": "ICMP",
  "af": 4,
  "dst_name": "8.8.8.8",
  "dst_addr": "8.8.8.8",
  "src_addr": "192.168.1.1",
  "from": "192.168.1.1",
  "destination_ip_responded": true,
  "result": [
    {
      "hop": 1,
      "result": [
        {"from": "10.0.0.1", "rtt": 1.234, "ttl": 64, "size": 28},
        {"from": "10.0.0.1", "rtt": 1.456, "ttl": 64, "size": 28},
        {"from": "10.0.0.1", "rtt": 1.567, "ttl": 64, "size": 28}
      ]
    },
    {
      "hop": 2,
      "result": [
        {"from": "8.8.4.4", "rtt": 5.123, "ttl": 63, "size": 28}
      ]
    },
    {
      "hop": 3,
      "result": [
        {"x": "*"}  // Timeout!
      ]
    }
  ]
}
```

### Key Patterns
- JSONL format (newline-delimited)
- bz2 compressed (~2GB/hour)
- ~12 hops per traceroute average
- Multiple probe attempts per hop (usually 3)
- Timeouts: `{"x": "*"}` instead of response data
- 99% have dst_addr and src_addr (handle missing 1%)

## Module Implementation Examples

### RIPE Atlas Module

```go
// pkg/modules/atlas_traceroute.go
type AtlasTracerouteModule struct {
    storage *Storage
    baseURL string
}

func (m *AtlasTracerouteModule) Process(ctx context.Context) error {
    // Download and decompress
    now := time.Now().UTC().Add(-1 * time.Hour)
    url := fmt.Sprintf("%s/%s/traceroute-%s.bz2",
        m.baseURL,
        now.Format("2006-01-02"),
        now.Format("2006-01-02T1504"))

    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // Stream decompress and parse JSONL
    reader := bzip2.NewReader(resp.Body)
    scanner := bufio.NewScanner(reader)

    count := 0
    for scanner.Scan() {
        var atlasData AtlasTraceroute
        if err := json.Unmarshal(scanner.Bytes(), &atlasData); err != nil {
            continue
        }

        // Parse and store
        if err := m.storeAtlasTraceroute(atlasData); err != nil {
            log.Printf("Error storing: %v", err)
            continue
        }
        count++
    }

    m.storage.UpdateModuleState(m.Name(), true, int64(count))
    return scanner.Err()
}

type AtlasTraceroute struct {
    MsmID      int64  `json:"msm_id"`
    PrbID      int    `json:"prb_id"`
    Timestamp  int64  `json:"timestamp"`
    Proto      string `json:"proto"`
    AF         int    `json:"af"`
    DstAddr    string `json:"dst_addr"`
    SrcAddr    string `json:"src_addr"`
    Result     []AtlasHop `json:"result"`
}

type AtlasHop struct {
    Hop    int           `json:"hop"`
    Result []AtlasReply  `json:"result"`
}

type AtlasReply struct {
    From string  `json:"from"`
    RTT  float64 `json:"rtt"`
    TTL  int     `json:"ttl"`
    Size int     `json:"size"`
    X    string  `json:"x"`    // "*" for timeout
    Err  string  `json:"err"`  // Error code
}

func (m *AtlasTracerouteModule) storeAtlasTraceroute(atlas AtlasTraceroute) error {
    // Generate source measurement ID
    sourceID := fmt.Sprintf("msm_%d_prb_%d", atlas.MsmID, atlas.PrbID)
    timestamp := time.Unix(atlas.Timestamp, 0)

    // Prepare statement with ON CONFLICT for idempotency
    stmt, err := m.storage.DB().Prepare(`
        INSERT INTO traceroute_hops
            (timestamp, source, source_measurement_id, hop_num,
             hop_src_ip, hop_dst_ip, target_ip, rtt_ms, asn, timeout)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (source, source_measurement_id, timestamp, hop_num)
        DO NOTHING
    `)
    if err != nil {
        return err
    }
    defer stmt.Close()

    prevIP := atlas.SrcAddr
    for _, hop := range atlas.Result {
        // Handle multiple probe responses
        var hopIP string
        var rtt float64
        isTimeout := false

        if len(hop.Result) > 0 {
            // Check if timeout
            if hop.Result[0].X == "*" {
                isTimeout = true
                hopIP = ""  // NULL
            } else {
                hopIP = hop.Result[0].From
                // Average RTT across all probe attempts
                totalRTT := 0.0
                validRTTs := 0
                for _, reply := range hop.Result {
                    if reply.RTT > 0 {
                        totalRTT += reply.RTT
                        validRTTs++
                    }
                }
                if validRTTs > 0 {
                    rtt = totalRTT / float64(validRTTs)
                }
            }
        }

        // TODO: Lookup ASN for hopIP (from ip_geolocation table or API)
        var asn *int // Will be populated by ASN lookup

        _, err := stmt.Exec(
            timestamp,
            "atlas-traceroute",
            sourceID,
            hop.Hop,
            prevIP,
            hopIP,
            atlas.DstAddr,
            rtt,
            asn,
            isTimeout,
        )
        if err != nil {
            return err
        }

        if hopIP != "" {
            prevIP = hopIP
        }
    }

    return nil
}
```

### Scamper VPS Module

```go
// pkg/modules/scamper.go
type ScamperModule struct {
    storage  *Storage
    hostname string  // VPS hostname
}

func (m *ScamperModule) Process(ctx context.Context) error {
    // Run scamper and get results
    traces := m.runScamper(ctx)

    for _, trace := range traces {
        // Generate unique source ID
        sourceID := fmt.Sprintf("vps_%s_%d_%s",
            m.hostname,
            trace.Timestamp.Unix(),
            trace.TargetIP)

        // Store traceroute (idempotent!)
        err := StoreTraceroute(
            m.storage.DB(),
            fmt.Sprintf("scamper-%s", m.hostname),
            sourceID,
            trace.Timestamp,
            trace.SrcIP,
            trace.TargetIP,
            trace.Hops,
        )
        if err != nil {
            log.Printf("Error storing traceroute: %v", err)
            continue
        }
    }

    return nil
}
```

## Common Queries

### All hops to a specific destination
```sql
SELECT hop_num, hop_src_ip, hop_dst_ip, rtt_ms, source
FROM traceroute_hops
WHERE target_ip = '8.8.8.8'
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC, hop_num;
```

### Reconstruct a specific traceroute by source ID
```sql
SELECT hop_num, hop_src_ip, hop_dst_ip, rtt_ms, asn
FROM traceroute_hops
WHERE source = 'atlas-traceroute'
  AND source_measurement_id = 'msm_12345_prb_5678'
ORDER BY hop_num;
```

### Find all paths through a specific IP
```sql
SELECT source, source_measurement_id, hop_num, target_ip, timestamp
FROM traceroute_hops
WHERE hop_dst_ip = '10.0.0.1'
  AND timestamp > NOW() - INTERVAL '1 day'
ORDER BY timestamp DESC;
```

### Count unique traceroutes (no duplicates!)
```sql
SELECT target_ip,
       COUNT(DISTINCT (source, source_measurement_id)) as unique_traces
FROM traceroute_hops
WHERE timestamp > NOW() - INTERVAL '1 day'
GROUP BY target_ip
ORDER BY unique_traces DESC;
```

### Check for reprocessed data
```sql
-- Find if same measurement was processed multiple times
-- (Should return no rows with UNIQUE constraint)
SELECT source, source_measurement_id, timestamp, hop_num, COUNT(*)
FROM traceroute_hops
GROUP BY source, source_measurement_id, timestamp, hop_num
HAVING COUNT(*) > 1;
```

## Crash Recovery Example

```go
// Module crashes during processing
func (m *AtlasTracerouteModule) Process(ctx context.Context) error {
    file := "traceroute-2025-10-29T1000.bz2"

    // Start processing
    for i, measurement := range measurements {
        StoreTraceroute(...)  // Stores measurement 1, 2, 3...

        if i == 500 {
            // CRASH! (or network failure, etc.)
            return errors.New("crash")
        }
    }

    // ... system restarts ...

    // Reprocess same file - NO PROBLEM!
    for _, measurement := range measurements {
        StoreTraceroute(...)  // ON CONFLICT DO NOTHING
        // Measurements 1-500: skipped (already exist)
        // Measurements 501+: inserted (new)
    }

    // Result: Clean data, no duplicates!
}
```

## Performance Characteristics

### Storage
- 10M traceroutes/day × 15 hops average = 150M rows/day
- ~120 bytes/row (with source IDs) = 18GB/day uncompressed
- TimescaleDB compression (10x) = 1.8GB/day
- 90 day retention = 162GB total

### Insert Speed
- Batch insert with prepared statement: ~1-2ms for 15 hops
- ON CONFLICT check is very fast (indexed UNIQUE constraint)
- Can process millions of traceroutes/day per module instance

### Query Speed
- By destination: Fast (indexed on target_ip + timestamp)
- By source ID: Fast (indexed on source + source_measurement_id)
- By hop IP: Fast (indexed on hop_dst_ip)
- No JOINs needed, TimescaleDB auto-partitioned

## Data Retention

```sql
-- Auto-compress data older than 7 days (10x compression)
ALTER TABLE traceroute_hops SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'source'
);

SELECT add_compression_policy('traceroute_hops', INTERVAL '7 days');

-- Auto-delete data older than 90 days
SELECT add_retention_policy('traceroute_hops', INTERVAL '90 days');
```

## Benefits of This Hybrid Design

1. ✅ **Idempotent**: Safe to reprocess data, no duplicates
2. ✅ **Crash Recovery**: Module can restart and continue safely
3. ✅ **Horizontal Scaling**: Multiple instances can run concurrently
4. ✅ **Source Traceability**: Can correlate back to original measurement
5. ✅ **Fast Queries**: Auto-increment ID for internal operations
6. ✅ **No Coordination**: No locks or distributed coordination needed
7. ✅ **Simple**: Still single table, flat structure
8. ✅ **Scalable**: TimescaleDB partitioning and compression

## When This Design Shines

This design is perfect for:
- Production systems with reliability requirements
- Multiple module instances processing concurrently
- Need for crash recovery without data loss
- Reprocessing historical data
- Correlating back to source measurements
- Clean, duplicate-free data

**Cost:** Just 2 extra TEXT columns + UNIQUE constraint
**Benefit:** Production-ready reliability and idempotency