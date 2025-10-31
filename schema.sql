-- Internet Measurement System - Database Schema
-- PostgreSQL with TimescaleDB

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================================================
-- TRACEROUTE MEASUREMENTS
-- ============================================================================

-- Traceroute hops - one row per hop (scalable to 100M+ traceroutes)
-- Uses hybrid design: auto-increment ID + natural source IDs for idempotency
CREATE TABLE IF NOT EXISTS traceroute_hops (
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
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_hops_target ON traceroute_hops(target_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hops_dst_ip ON traceroute_hops(hop_dst_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hops_source ON traceroute_hops(source, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hops_source_measurement ON traceroute_hops(source, source_measurement_id);
CREATE INDEX IF NOT EXISTS idx_hops_proto ON traceroute_hops(proto);
CREATE INDEX IF NOT EXISTS idx_hops_probe ON traceroute_hops(probe_id) WHERE probe_id IS NOT NULL;

-- Auto-compress data older than 7 days (10x compression)
ALTER TABLE traceroute_hops SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'source'
);

SELECT add_compression_policy('traceroute_hops', INTERVAL '7 days', if_not_exists => TRUE);

-- Auto-delete data older than 90 days
SELECT add_retention_policy('traceroute_hops', INTERVAL '90 days', if_not_exists => TRUE);

-- ============================================================================
-- WHOIS DATA (RIR Registry Information)
-- ============================================================================

-- IPv4/IPv6 allocations from WHOIS databases
CREATE TABLE IF NOT EXISTS whois_inetnum (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Natural identifiers (idempotency)
    source TEXT NOT NULL,            -- 'ripe-whois', 'arin-whois', etc.
    range_start INET NOT NULL,
    range_end INET NOT NULL,

    -- Core fields
    netname TEXT NOT NULL,
    country TEXT,
    org_id TEXT,
    status TEXT,

    -- Contact references
    admin_c TEXT[],
    tech_c TEXT[],

    -- Descriptions (can be multiline)
    descr TEXT[],

    -- Dates from object
    created TIMESTAMPTZ,
    last_modified TIMESTAMPTZ NOT NULL,

    -- Maintainer info
    mnt_by TEXT[],

    -- Flexible storage for RIR-specific fields
    extra_attrs JSONB,

    PRIMARY KEY (timestamp, id),
    UNIQUE (source, range_start, range_end, last_modified, timestamp)
);

SELECT create_hypertable('whois_inetnum', 'timestamp',
    chunk_time_interval => INTERVAL '30 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_inetnum_source ON whois_inetnum(source);
CREATE INDEX IF NOT EXISTS idx_inetnum_country ON whois_inetnum(country) WHERE country IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_inetnum_org ON whois_inetnum(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_inetnum_status ON whois_inetnum(status);

-- Autonomous Systems from WHOIS
CREATE TABLE IF NOT EXISTS whois_aut_num (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Natural identifiers
    source TEXT NOT NULL,
    asn BIGINT NOT NULL,

    -- Core fields
    as_name TEXT NOT NULL,
    descr TEXT[],
    country TEXT,
    org_id TEXT,
    status TEXT,

    -- Contact references
    admin_c TEXT[],
    tech_c TEXT[],

    -- Routing policy (JSONB - too varied for columns)
    import_policy JSONB,
    export_policy JSONB,

    -- Dates
    created TIMESTAMPTZ,
    last_modified TIMESTAMPTZ NOT NULL,

    -- Maintainer
    mnt_by TEXT[],

    -- Flexible storage
    extra_attrs JSONB,

    PRIMARY KEY (timestamp, id),
    UNIQUE (source, asn, last_modified, timestamp)
);

SELECT create_hypertable('whois_aut_num', 'timestamp',
    chunk_time_interval => INTERVAL '30 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_autnum_source ON whois_aut_num(source);
CREATE INDEX IF NOT EXISTS idx_autnum_asn ON whois_aut_num(asn);
CREATE INDEX IF NOT EXISTS idx_autnum_country ON whois_aut_num(country) WHERE country IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_autnum_org ON whois_aut_num(org_id) WHERE org_id IS NOT NULL;

-- Routing table entries from WHOIS
CREATE TABLE IF NOT EXISTS whois_routes (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Natural identifiers
    source TEXT NOT NULL,
    prefix CIDR NOT NULL,
    origin_asn BIGINT NOT NULL,

    -- Core fields
    descr TEXT[],
    mnt_by TEXT[],
    member_of TEXT[],  -- AS-SET memberships

    -- Dates
    created TIMESTAMPTZ,
    last_modified TIMESTAMPTZ NOT NULL,

    -- Flexible storage
    extra_attrs JSONB,

    PRIMARY KEY (timestamp, id),
    UNIQUE (source, prefix, origin_asn, last_modified, timestamp)
);

SELECT create_hypertable('whois_routes', 'timestamp',
    chunk_time_interval => INTERVAL '30 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_routes_source ON whois_routes(source);
CREATE INDEX IF NOT EXISTS idx_routes_prefix ON whois_routes USING GIST(prefix inet_ops);
CREATE INDEX IF NOT EXISTS idx_routes_origin ON whois_routes(origin_asn);

-- Organizations/LIRs from WHOIS
CREATE TABLE IF NOT EXISTS whois_organisations (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Natural identifiers
    source TEXT NOT NULL,
    org_id TEXT NOT NULL,

    -- Core fields
    org_name TEXT NOT NULL,
    org_type TEXT,
    country TEXT,
    address TEXT[],
    email TEXT[],
    phone TEXT[],

    -- Contact references
    admin_c TEXT[],
    tech_c TEXT[],

    -- Dates
    created TIMESTAMPTZ,
    last_modified TIMESTAMPTZ NOT NULL,

    -- Maintainer
    mnt_ref TEXT[],
    mnt_by TEXT[],

    -- Flexible storage
    extra_attrs JSONB,

    PRIMARY KEY (timestamp, id),
    UNIQUE (source, org_id, last_modified, timestamp)
);

SELECT create_hypertable('whois_organisations', 'timestamp',
    chunk_time_interval => INTERVAL '90 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_org_source ON whois_organisations(source);
CREATE INDEX IF NOT EXISTS idx_org_id ON whois_organisations(org_id);
CREATE INDEX IF NOT EXISTS idx_org_country ON whois_organisations(country) WHERE country IS NOT NULL;

-- Generic WHOIS objects (as-set, route-set, mntner, person, role, domain, etc.)
CREATE TABLE IF NOT EXISTS whois_objects (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Natural identifiers
    source TEXT NOT NULL,
    object_type TEXT NOT NULL,       -- 'as-set', 'route-set', 'mntner', etc.
    object_key TEXT NOT NULL,        -- Primary identifier from object

    -- All attributes as JSONB
    attributes JSONB NOT NULL,

    -- Dates
    last_modified TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (timestamp, id),
    UNIQUE (source, object_type, object_key, last_modified, timestamp)
);

SELECT create_hypertable('whois_objects', 'timestamp',
    chunk_time_interval => INTERVAL '90 days',
    if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_whois_obj_source ON whois_objects(source);
CREATE INDEX IF NOT EXISTS idx_whois_obj_type ON whois_objects(object_type);
CREATE INDEX IF NOT EXISTS idx_whois_obj_key ON whois_objects(object_key);
CREATE INDEX IF NOT EXISTS idx_whois_obj_attrs ON whois_objects USING GIN(attributes);

-- ============================================================================
-- SUPPORTING TABLES
-- ============================================================================

-- Module execution state
CREATE TABLE IF NOT EXISTS module_state (
    module_name TEXT PRIMARY KEY,
    last_run TIMESTAMPTZ,
    last_success TIMESTAMPTZ,
    last_error TEXT,
    records_processed BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Simple key-value configuration storage
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value JSONB,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Reconstruct full traceroute paths
CREATE OR REPLACE VIEW traceroute_paths AS
SELECT
    source,
    source_measurement_id,
    probe_id,
    timestamp,
    target_ip,
    proto,
    array_agg(hop_dst_ip ORDER BY hop_num) as path_ips,
    array_agg(asn ORDER BY hop_num) FILTER (WHERE asn IS NOT NULL) as path_asns,
    avg(rtt_ms) FILTER (WHERE rtt_ms IS NOT NULL) as avg_rtt,
    max(hop_num) as hop_count
FROM traceroute_hops
GROUP BY source, source_measurement_id, probe_id, timestamp, target_ip, proto;

-- Module health status
CREATE OR REPLACE VIEW module_status AS
SELECT
    module_name,
    last_run,
    last_success,
    CASE
        WHEN last_success > NOW() - INTERVAL '1 day' THEN 'healthy'
        WHEN last_success > NOW() - INTERVAL '3 days' THEN 'warning'
        ELSE 'error'
    END as status,
    records_processed,
    last_error
FROM module_state
ORDER BY last_run DESC NULLS LAST;

-- Initialize module state for atlas-traceroute
INSERT INTO module_state (module_name, records_processed)
VALUES ('atlas-traceroute', 0)
ON CONFLICT (module_name) DO NOTHING;
