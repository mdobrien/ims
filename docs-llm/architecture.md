# Internet Measurement System - Modular Architecture

## Overview

This document describes the modular, extensible architecture for an Internet Measurement System (IMS). The system creates a comprehensive map of the internet by ingesting and correlating multiple data sources - BGP routing, network measurements, registry data, certificates, and more - enabling analysis and pivoting across diverse internet infrastructure data.

## Core Design Principles

1. **Simplicity First**: Avoid premature complexity, start simple and evolve
2. **Module per Data Source**: Each specific data source has its own module file
3. **Unified Schema**: All tables defined in a single schema.sql file
4. **Built-in Scheduler**: Simple scheduler with module-defined intervals
5. **Data-Type Agnostic Storage**: Flexible JSONB storage for observations

## Project Structure

```
/cmd/ims/main.go          # Main application entry point
/pkg/
  ├── module.go           # Module interface definition
  ├── storage.go          # Database operations
  ├── scheduler.go        # Scheduling logic
  └── modules/
      ├── atlas_traceroute.go  # RIPE Atlas traceroute module
      ├── atlas_ping.go        # RIPE Atlas ping module
      ├── atlas_dns.go         # RIPE Atlas DNS module
      ├── atlas_http.go        # RIPE Atlas HTTP module
      ├── atlas_sslcert.go     # RIPE Atlas SSL cert module
      ├── atlas_ntp.go         # RIPE Atlas NTP module
      ├── atlas_connection.go  # RIPE Atlas connection module
      ├── bgp_routeviews.go    # RouteViews BGP module
      ├── bgp_riperis.go       # RIPE RIS BGP module
      ├── rir_arin.go          # ARIN registry module
      ├── rir_ripe.go          # RIPE registry module
      ├── rir_apnic.go         # APNIC registry module
      ├── rir_lacnic.go        # LACNIC registry module
      ├── rir_afrinic.go       # AFRINIC registry module
      ├── peeringdb.go         # PeeringDB module
      └── ct_logs.go           # Certificate Transparency module
/schema.sql               # ALL database tables in one file
/config.json              # Configuration file
```

## Core Components

### Module Interface

Simple, minimal interface that all modules implement:

```go
// pkg/module.go
package pkg

import (
    "context"
    "time"
)

// Module represents a data source processor
type Module interface {
    Name() string
    Schedule() Schedule
    Process(ctx context.Context) error
}

// Schedule defines when and how to run a module
type Schedule struct {
    Interval    time.Duration
    Priority    int      // Higher = more important
    Timeout     time.Duration
    MaxRetries  int
}
```

### Storage Layer

Simple database interface for all modules to use:

```go
// pkg/storage.go
package pkg

import (
    "database/sql"
    "encoding/json"
)

type Storage struct {
    db *sql.DB
}

// StoreObservation stores any type of observation
func (s *Storage) StoreObservation(obsType string, source string, timestamp time.Time, data interface{}) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return err
    }

    _, err = s.db.Exec(`
        INSERT INTO observations (observation_type, source, timestamp, data)
        VALUES ($1, $2, $3, $4)
    `, obsType, source, timestamp, jsonData)

    return err
}

// UpdateModuleState tracks module execution
func (s *Storage) UpdateModuleState(moduleName string, success bool, recordsProcessed int64) error {
    if success {
        _, err := s.db.Exec(`
            UPDATE module_state
            SET last_run = NOW(), last_success = NOW(), records_processed = records_processed + $2
            WHERE module_name = $1
        `, moduleName, recordsProcessed)
        return err
    }
    // Handle error case...
}
```

### Scheduler

Simple scheduler that runs modules based on their intervals:

```go
// pkg/scheduler.go
package pkg

import (
    "context"
    "log"
    "time"
)

type Scheduler struct {
    modules []Module
    storage *Storage
}

func (s *Scheduler) Run(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Minute)
    lastRun := make(map[string]time.Time)

    for {
        select {
        case <-ticker.C:
            for _, module := range s.modules {
                if time.Since(lastRun[module.Name()]) >= module.Schedule().Interval {
                    go s.runModule(ctx, module)
                    lastRun[module.Name()] = time.Now()
                }
            }
        case <-ctx.Done():
            return
        }
    }
}

func (s *Scheduler) runModule(ctx context.Context, module Module) {
    log.Printf("Running module: %s", module.Name())

    ctx, cancel := context.WithTimeout(ctx, module.Schedule().Timeout)
    defer cancel()

    start := time.Now()
    err := module.Process(ctx)

    if err != nil {
        log.Printf("Error in module %s: %v", module.Name(), err)
        s.storage.UpdateModuleState(module.Name(), false, 0)
    } else {
        log.Printf("Module %s completed in %v", module.Name(), time.Since(start))
        // Module should call UpdateModuleState itself with record count
    }
}
```

## Module Implementations

### RIPE Atlas Traceroute Module

```go
// pkg/modules/atlas_traceroute.go
package modules

import (
    "compress/bzip2"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type AtlasTracerouteModule struct {
    storage *Storage
    baseURL string
}

func NewAtlasTraceroute(storage *Storage) *AtlasTracerouteModule {
    return &AtlasTracerouteModule{
        storage: storage,
        baseURL: "https://data-store.ripe.net/datasets/atlas-daily-dumps",
    }
}

func (m *AtlasTracerouteModule) Name() string {
    return "atlas-traceroute"
}

func (m *AtlasTracerouteModule) Schedule() Schedule {
    return Schedule{
        Interval:   1 * time.Hour,  // Process hourly dumps
        Priority:   10,              // High priority (valuable data)
        Timeout:    30 * time.Minute,
        MaxRetries: 3,
    }
}

func (m *AtlasTracerouteModule) Process(ctx context.Context) error {
    // Build URL for current hour's data
    now := time.Now().UTC().Add(-1 * time.Hour) // Process previous hour
    url := fmt.Sprintf("%s/%s/traceroute-%s.bz2",
        m.baseURL,
        now.Format("2006-01-02"),
        now.Format("2006-01-02T1504"))

    // Download and decompress
    resp, err := http.Get(url)
    if err != nil {
        return fmt.Errorf("download failed: %w", err)
    }
    defer resp.Body.Close()

    reader := bzip2.NewReader(resp.Body)
    decoder := json.NewDecoder(reader)

    // Process measurements
    count := int64(0)
    for decoder.More() {
        var measurement map[string]interface{}
        if err := decoder.Decode(&measurement); err != nil {
            continue
        }

        // Store observation
        err := m.storage.StoreObservation(
            "traceroute_path",
            "atlas-traceroute",
            now,
            measurement,
        )
        if err != nil {
            continue
        }

        count++

        // Extract and store entities/relationships if needed
        m.extractEntities(measurement)
    }

    m.storage.UpdateModuleState(m.Name(), true, count)
    return nil
}

func (m *AtlasTracerouteModule) extractEntities(measurement map[string]interface{}) {
    // Extract AS paths, IP addresses, etc.
    // Store as entities and relationships
}
```

### RIPE Atlas Ping Module

```go
// pkg/modules/atlas_ping.go
package modules

type AtlasPingModule struct {
    storage *Storage
    baseURL string
}

func NewAtlasPing(storage *Storage) *AtlasPingModule {
    return &AtlasPingModule{
        storage: storage,
        baseURL: "https://data-store.ripe.net/datasets/atlas-daily-dumps",
    }
}

func (m *AtlasPingModule) Name() string {
    return "atlas-ping"
}

func (m *AtlasPingModule) Schedule() Schedule {
    return Schedule{
        Interval:   1 * time.Hour,
        Priority:   8,              // Lower than traceroute
        Timeout:    30 * time.Minute,
        MaxRetries: 3,
    }
}

func (m *AtlasPingModule) Process(ctx context.Context) error {
    // Similar to traceroute but for ping data
    // Downloads ping-YYYY-MM-DDTHHMM.bz2 files (2GB)
}
```

### BGP RouteViews Module

```go
// pkg/modules/bgp_routeviews.go
package modules

type BGPRouteViewsModule struct {
    storage    *Storage
    collectors []string
}

func NewBGPRouteViews(storage *Storage) *BGPRouteViewsModule {
    return &BGPRouteViewsModule{
        storage: storage,
        collectors: []string{
            "route-views2",
            "route-views.chicago",
            "route-views.sydney",
        },
    }
}

func (m *BGPRouteViewsModule) Name() string {
    return "bgp-routeviews"
}

func (m *BGPRouteViewsModule) Schedule() Schedule {
    return Schedule{
        Interval:   2 * time.Hour,  // BGP snapshots every 2 hours
        Priority:   7,
        Timeout:    1 * time.Hour,
        MaxRetries: 2,
    }
}

func (m *BGPRouteViewsModule) Process(ctx context.Context) error {
    // Download MRT files from RouteViews collectors
    // Parse BGP announcements
    // Store as observations
}
```

### RIR Module Example

```go
// pkg/modules/rir_ripe.go
package modules

type RIRRipeModule struct {
    storage *Storage
}

func NewRIRRipe(storage *Storage) *RIRRipeModule {
    return &RIRRipeModule{storage: storage}
}

func (m *RIRRipeModule) Name() string {
    return "rir-ripe"
}

func (m *RIRRipeModule) Schedule() Schedule {
    return Schedule{
        Interval:   24 * time.Hour,  // Daily updates
        Priority:   5,
        Timeout:    1 * time.Hour,
        MaxRetries: 3,
    }
}

func (m *RIRRipeModule) Process(ctx context.Context) error {
    // Download delegated stats file
    // Parse allocations
    // Update entity information
}
```

## Database Schema (schema.sql)

All tables are defined in a single schema.sql file:

```sql
-- schema.sql - Complete database schema

-- ============================================================================
-- TRACEROUTE MEASUREMENTS
-- ============================================================================

-- Traceroute hops - one row per hop (scalable to 100M+ traceroutes)
-- Uses hybrid design: auto-increment ID + natural source IDs for idempotency
CREATE TABLE traceroute_hops (
    id BIGSERIAL,                       -- Auto-increment for fast queries
    timestamp TIMESTAMPTZ NOT NULL,     -- When this traceroute ran

    -- Natural identifiers (enables idempotency and crash recovery)
    source TEXT NOT NULL,               -- 'atlas-traceroute', 'scamper-vps1', etc.
    source_measurement_id TEXT NOT NULL,-- Source's native ID (e.g., 'msm_123456_prb_5678')
    probe_id TEXT,                      -- Probe identifier (Atlas probe ID, VPS hostname)

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
CREATE INDEX idx_hops_proto ON traceroute_hops(proto);
CREATE INDEX idx_hops_probe ON traceroute_hops(probe_id) WHERE probe_id IS NOT NULL;

-- Auto-compress data older than 7 days (10x compression)
ALTER TABLE traceroute_hops SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'source'
);

SELECT add_compression_policy('traceroute_hops', INTERVAL '7 days');

-- Auto-delete data older than 90 days
SELECT add_retention_policy('traceroute_hops', INTERVAL '90 days');

-- ============================================================================
-- OTHER MEASUREMENT TYPES (TODO: Expand with ping, DNS, BGP, etc.)
-- ============================================================================

-- TODO: Add ping measurements table
-- TODO: Add DNS measurements table
-- TODO: Add BGP announcements table

-- ============================================================================
-- SUPPORTING TABLES
-- ============================================================================

-- Module execution state
CREATE TABLE module_state (
    module_name TEXT PRIMARY KEY,
    last_run TIMESTAMPTZ,
    last_success TIMESTAMPTZ,
    last_error TEXT,
    records_processed BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Simple key-value configuration storage
CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value JSONB,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Reconstruct full traceroute paths
CREATE VIEW traceroute_paths AS
SELECT
    source,
    source_measurement_id,
    timestamp,
    target_ip,
    array_agg(hop_dst_ip ORDER BY hop_num) as path_ips,
    array_agg(asn ORDER BY hop_num) FILTER (WHERE asn IS NOT NULL) as path_asns,
    avg(rtt_ms) FILTER (WHERE rtt_ms IS NOT NULL) as avg_rtt,
    max(hop_num) as hop_count
FROM traceroute_hops
GROUP BY source, source_measurement_id, timestamp, target_ip;

-- Module health status
CREATE VIEW module_status AS
SELECT
    module_name,
    last_run,
    last_success,
    CASE
        WHEN last_success > NOW() - INTERVAL '1 day' THEN 'healthy'
        WHEN last_success > NOW() - INTERVAL '3 days' THEN 'warning'
        ELSE 'error'
    END as status,
    records_processed
FROM module_state
ORDER BY last_run DESC;
```

## Configuration

Simple JSON configuration file:

```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "database": "ims",
    "user": "ims_user",
    "password": "password",
    "max_connections": 20
  },
  "modules": {
    "atlas-traceroute": {
      "enabled": true,
      "override_interval": null
    },
    "atlas-ping": {
      "enabled": true,
      "override_interval": null
    },
    "atlas-dns": {
      "enabled": true,
      "override_interval": null
    },
    "atlas-http": {
      "enabled": false,
      "override_interval": null
    },
    "atlas-sslcert": {
      "enabled": false,
      "override_interval": null
    },
    "bgp-routeviews": {
      "enabled": true,
      "collectors": ["route-views2", "route-views.chicago"]
    },
    "rir-ripe": {
      "enabled": true,
      "override_interval": "12h"
    },
    "peeringdb": {
      "enabled": true,
      "override_interval": "6h"
    }
  },
  "scheduler": {
    "check_interval": "1m",
    "max_concurrent": 5
  }
}
```

## Main Application

Simple main.go that ties everything together:

```go
// cmd/ims/main.go
package main

import (
    "context"
    "database/sql"
    "log"
    "os"
    "os/signal"

    "ims/pkg"
    "ims/pkg/modules"

    _ "github.com/lib/pq"
)

func main() {
    // Load config
    config := loadConfig("config.json")

    // Connect to database
    db, err := sql.Open("postgres", config.Database.DSN())
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Initialize storage
    storage := pkg.NewStorage(db)

    // Create and register modules
    scheduler := pkg.NewScheduler(storage)

    // RIPE Atlas modules
    scheduler.Register(modules.NewAtlasTraceroute(storage))
    scheduler.Register(modules.NewAtlasPing(storage))
    scheduler.Register(modules.NewAtlasDNS(storage))
    scheduler.Register(modules.NewAtlasHTTP(storage))
    scheduler.Register(modules.NewAtlasSSLCert(storage))
    scheduler.Register(modules.NewAtlasNTP(storage))
    scheduler.Register(modules.NewAtlasConnection(storage))

    // BGP modules
    scheduler.Register(modules.NewBGPRouteViews(storage))
    scheduler.Register(modules.NewBGPRIPERIS(storage))

    // RIR modules
    scheduler.Register(modules.NewRIRRipe(storage))
    scheduler.Register(modules.NewRIRARIN(storage))
    scheduler.Register(modules.NewRIRAPNIC(storage))

    // Other modules
    scheduler.Register(modules.NewPeeringDB(storage))

    // Start scheduler
    ctx, cancel := context.WithCancel(context.Background())
    go scheduler.Run(ctx)

    // Wait for interrupt
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c

    log.Println("Shutting down...")
    cancel()
}
```

## Key Benefits of This Architecture

1. **Simple and Clear**: Each module is a single file with clear purpose
2. **Unified Schema**: All tables in one schema.sql file, easy to understand database structure
3. **No Premature Abstraction**: Direct implementation without unnecessary layers
4. **Easy to Add Modules**: Copy existing module, change data source URL and parsing logic
5. **Flexible Storage**: JSONB allows storing different data types without schema changes
6. **Easy Testing**: Each module can be tested independently
7. **Clear Dependencies**: Minimal interfaces, clear data flow

## Development Workflow

1. **Add New Data Source**:
   - Create new file in `/pkg/modules/`
   - Implement the Module interface (Name, Schedule, Process)
   - Register in main.go
   - No schema changes needed (uses observations table)

2. **Debug Issues**:
   - Check module_state table for last run status
   - Query observations table for recent data
   - Each module logs its progress

3. **Scale Up**:
   - Start with single database
   - Add TimescaleDB when data volume increases
   - Add connection pooling when needed
   - Consider partitioning observations table by month

## Migration Path

As the system grows:

1. **Phase 1** (Current): Simple modules, single database
2. **Phase 2**: Add caching layer for frequently accessed data
3. **Phase 3**: Partition observations table, add read replicas
4. **Phase 4**: Consider specialized storage for different data types
5. **Phase 5**: Distributed processing if needed

The beauty is you can start simple and evolve based on actual needs rather than anticipated complexity.