-- WHOIS Materialized Views for AS/IP/Organization Correlation
-- These views provide efficient access to correlated WHOIS data
-- combining AS numbers, IP prefixes, organizations, and geographic information

-- Drop existing views if they exist
DROP MATERIALIZED VIEW IF EXISTS mv_as_route_summary CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_as_allocation_summary CASCADE;

-- =============================================================================
-- Primary View: AS to Route/Prefix Mapping with Organization Details
-- =============================================================================
-- This view correlates:
-- - Autonomous Systems (AS) with their announced routes
-- - Organizations that manage the AS
-- - Geographic information (countries)
-- - Route descriptions and metadata

CREATE MATERIALIZED VIEW mv_as_route_summary AS
WITH
-- Get latest AS information per ASN and source
latest_as AS (
  SELECT DISTINCT ON (source, asn)
    source,
    asn,
    as_name,
    country AS as_country,
    org_id AS as_org_id,
    descr AS as_descr,
    status AS as_status,
    admin_c,
    tech_c,
    mnt_by,
    created AS as_created,
    timestamp,
    extra_attrs AS as_extra_attrs
  FROM whois_aut_num
  ORDER BY source, asn, timestamp DESC
),
-- Get latest organization info per org_id and source
latest_org AS (
  SELECT DISTINCT ON (source, org_id)
    source,
    org_id,
    org_name,
    org_type,
    country AS org_country,
    address,
    email,
    phone,
    admin_c AS org_admin_c,
    tech_c AS org_tech_c,
    created AS org_created,
    extra_attrs AS org_extra_attrs
  FROM whois_organisations
  ORDER BY source, org_id, timestamp DESC
),
-- Get latest route information
latest_routes AS (
  SELECT DISTINCT ON (source, prefix, origin_asn)
    source,
    prefix,
    origin_asn,
    descr AS route_descr,
    mnt_by AS route_mnt_by,
    member_of,
    created AS route_created,
    timestamp,
    extra_attrs AS route_extra_attrs
  FROM whois_routes
  WHERE origin_asn IS NOT NULL  -- Only include routes with known origin AS
  ORDER BY source, prefix, origin_asn, timestamp DESC
)
SELECT
  -- Identity
  r.source,
  r.origin_asn AS asn,
  a.as_name,
  r.prefix,

  -- Route metadata
  r.route_descr,
  r.route_mnt_by,
  r.member_of AS as_set_memberships,

  -- Geography (prefer AS country, fallback to org country)
  COALESCE(a.as_country, o.org_country) AS country,
  a.as_country,
  o.org_country,

  -- Organization details
  a.as_org_id AS org_id,
  o.org_name,
  o.org_type,

  -- AS metadata
  a.as_descr,
  a.as_status,
  a.admin_c AS as_admin_c,
  a.tech_c AS as_tech_c,
  a.mnt_by AS as_mnt_by,

  -- Contact info from organization
  o.address AS org_address,
  o.email AS org_email,
  o.phone AS org_phone,
  o.org_admin_c,
  o.org_tech_c,

  -- Network classification
  CASE
    WHEN family(r.prefix) = 4 THEN 'IPv4'
    WHEN family(r.prefix) = 6 THEN 'IPv6'
  END AS ip_version,

  masklen(r.prefix) AS prefix_length,
  host(r.prefix) AS prefix_start,
  host(broadcast(r.prefix)) AS prefix_end,

  -- Creation dates
  r.route_created,
  a.as_created,
  o.org_created,

  -- Timestamps for data freshness
  r.timestamp AS route_last_seen,
  a.timestamp AS as_last_seen,

  -- Extra attributes (JSONB) for extensibility
  r.route_extra_attrs,
  a.as_extra_attrs,
  o.org_extra_attrs

FROM latest_routes r
LEFT JOIN latest_as a ON r.source = a.source AND r.origin_asn = a.asn
LEFT JOIN latest_org o ON a.source = o.source AND a.as_org_id = o.org_id;

-- Create indexes for optimal query performance
CREATE UNIQUE INDEX idx_mv_as_route_unique ON mv_as_route_summary(source, asn, prefix);
CREATE INDEX idx_mv_as_route_asn ON mv_as_route_summary(asn);
CREATE INDEX idx_mv_as_route_prefix ON mv_as_route_summary USING GIST(prefix inet_ops);
CREATE INDEX idx_mv_as_route_source ON mv_as_route_summary(source);
CREATE INDEX idx_mv_as_route_country ON mv_as_route_summary(country) WHERE country IS NOT NULL;
CREATE INDEX idx_mv_as_route_org ON mv_as_route_summary(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX idx_mv_as_route_asn_source ON mv_as_route_summary(asn, source);
CREATE INDEX idx_mv_as_route_ip_version ON mv_as_route_summary(ip_version);
CREATE INDEX idx_mv_as_route_as_name ON mv_as_route_summary(as_name) WHERE as_name IS NOT NULL;

-- =============================================================================
-- Secondary View: AS to IP Allocation (inetnum) Mapping
-- =============================================================================
-- This view correlates:
-- - Autonomous Systems with their allocated IP ranges (from inetnum)
-- - Organizations that have IP allocations
-- - Network allocation status and metadata

CREATE MATERIALIZED VIEW mv_as_allocation_summary AS
WITH
-- Get latest AS information
latest_as AS (
  SELECT DISTINCT ON (source, asn)
    source,
    asn,
    as_name,
    country AS as_country,
    org_id AS as_org_id,
    descr AS as_descr,
    status AS as_status,
    admin_c,
    tech_c,
    mnt_by,
    created AS as_created,
    timestamp,
    extra_attrs AS as_extra_attrs
  FROM whois_aut_num
  ORDER BY source, asn, timestamp DESC
),
-- Get latest inetnum allocations
latest_inetnum AS (
  SELECT DISTINCT ON (source, range_start, range_end)
    source,
    range_start,
    range_end,
    netname,
    country AS alloc_country,
    org_id AS alloc_org_id,
    status,
    descr AS alloc_descr,
    admin_c AS alloc_admin_c,
    tech_c AS alloc_tech_c,
    mnt_by AS alloc_mnt_by,
    created AS alloc_created,
    timestamp,
    extra_attrs AS alloc_extra_attrs
  FROM whois_inetnum
  ORDER BY source, range_start, range_end, timestamp DESC
),
-- Get latest organization info
latest_org AS (
  SELECT DISTINCT ON (source, org_id)
    source,
    org_id,
    org_name,
    org_type,
    country AS org_country,
    address,
    email,
    phone,
    admin_c AS org_admin_c,
    tech_c AS org_tech_c,
    created AS org_created
  FROM whois_organisations
  ORDER BY source, org_id, timestamp DESC
),
-- Join AS to allocations via organization
as_allocations AS (
  SELECT
    a.source,
    a.asn,
    a.as_name,
    a.as_country,
    a.as_org_id,
    a.as_descr,
    a.as_status,
    a.admin_c,
    a.tech_c,
    a.mnt_by,
    a.as_created,
    a.timestamp AS as_timestamp,
    a.as_extra_attrs,
    i.range_start,
    i.range_end,
    i.netname,
    i.alloc_country,
    i.alloc_org_id,
    i.status AS allocation_status,
    i.alloc_descr,
    i.alloc_admin_c,
    i.alloc_tech_c,
    i.alloc_mnt_by,
    i.alloc_created,
    i.timestamp AS alloc_timestamp,
    i.alloc_extra_attrs
  FROM latest_as a
  INNER JOIN latest_inetnum i ON
    a.source = i.source AND
    (a.as_org_id = i.alloc_org_id OR
     -- Also try to match via routes for better correlation
     EXISTS (
       SELECT 1 FROM whois_routes r
       WHERE r.source = a.source
         AND r.origin_asn = a.asn
         AND r.prefix::inet <<= i.range_start::inet
     ))
)
SELECT
  -- Identity
  aa.source,
  aa.asn,
  aa.as_name,

  -- Allocation details
  aa.range_start,
  aa.range_end,
  aa.netname,
  aa.allocation_status,
  aa.alloc_descr,

  -- Geography (multiple fallbacks)
  COALESCE(aa.as_country, aa.alloc_country, o.org_country) AS country,
  aa.as_country,
  aa.alloc_country,
  o.org_country,

  -- Organization linking
  COALESCE(aa.as_org_id, aa.alloc_org_id) AS org_id,
  o.org_name,
  o.org_type,

  -- AS metadata
  aa.as_descr,
  aa.as_status,
  aa.admin_c AS as_admin_c,
  aa.tech_c AS as_tech_c,
  aa.mnt_by AS as_mnt_by,

  -- Allocation metadata
  aa.alloc_admin_c,
  aa.alloc_tech_c,
  aa.alloc_mnt_by,

  -- Contact info from organization
  o.address AS org_address,
  o.email AS org_email,
  o.phone AS org_phone,
  o.org_admin_c,
  o.org_tech_c,

  -- Network classification
  CASE
    WHEN family(aa.range_start) = 4 THEN 'IPv4'
    WHEN family(aa.range_start) = 6 THEN 'IPv6'
  END AS ip_version,

  -- Calculate allocation size (for IPv4)
  CASE
    WHEN family(aa.range_start) = 4 THEN
      (inet(aa.range_end) - inet(aa.range_start) + 1)::bigint
    ELSE NULL
  END AS allocation_size,

  -- Creation dates
  aa.alloc_created,
  aa.as_created,
  o.org_created,

  -- Timestamps
  aa.alloc_timestamp AS allocation_last_seen,
  aa.as_timestamp AS as_last_seen,

  -- Extra attributes
  aa.alloc_extra_attrs,
  aa.as_extra_attrs

FROM as_allocations aa
LEFT JOIN latest_org o ON aa.source = o.source AND COALESCE(aa.as_org_id, aa.alloc_org_id) = o.org_id;

-- Create indexes for optimal query performance
CREATE UNIQUE INDEX idx_mv_as_alloc_unique ON mv_as_allocation_summary(source, asn, range_start, range_end);
CREATE INDEX idx_mv_as_alloc_asn ON mv_as_allocation_summary(asn);
CREATE INDEX idx_mv_as_alloc_range_start ON mv_as_allocation_summary USING GIST(range_start inet_ops);
CREATE INDEX idx_mv_as_alloc_range_end ON mv_as_allocation_summary USING GIST(range_end inet_ops);
CREATE INDEX idx_mv_as_alloc_org ON mv_as_allocation_summary(org_id) WHERE org_id IS NOT NULL;
CREATE INDEX idx_mv_as_alloc_country ON mv_as_allocation_summary(country) WHERE country IS NOT NULL;
CREATE INDEX idx_mv_as_alloc_netname ON mv_as_allocation_summary(netname) WHERE netname IS NOT NULL;
CREATE INDEX idx_mv_as_alloc_ip_version ON mv_as_allocation_summary(ip_version);

-- =============================================================================
-- Refresh Functions
-- =============================================================================

-- Function to refresh all WHOIS materialized views
CREATE OR REPLACE FUNCTION refresh_whois_materialized_views(concurrent BOOLEAN DEFAULT TRUE)
RETURNS void AS $$
BEGIN
  IF concurrent THEN
    RAISE NOTICE 'Refreshing mv_as_route_summary (concurrent)...';
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_as_route_summary;

    RAISE NOTICE 'Refreshing mv_as_allocation_summary (concurrent)...';
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_as_allocation_summary;
  ELSE
    RAISE NOTICE 'Refreshing mv_as_route_summary...';
    REFRESH MATERIALIZED VIEW mv_as_route_summary;

    RAISE NOTICE 'Refreshing mv_as_allocation_summary...';
    REFRESH MATERIALIZED VIEW mv_as_allocation_summary;
  END IF;

  RAISE NOTICE 'All WHOIS materialized views refreshed successfully';
END;
$$ LANGUAGE plpgsql;

-- Initial population of the views
REFRESH MATERIALIZED VIEW mv_as_route_summary;
REFRESH MATERIALIZED VIEW mv_as_allocation_summary;

-- =============================================================================
-- View Statistics Function
-- =============================================================================

CREATE OR REPLACE FUNCTION whois_view_statistics()
RETURNS TABLE (
  view_name TEXT,
  row_count BIGINT,
  unique_asns BIGINT,
  unique_prefixes BIGINT,
  unique_orgs BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    'mv_as_route_summary'::TEXT,
    COUNT(*)::BIGINT,
    COUNT(DISTINCT asn)::BIGINT,
    COUNT(DISTINCT prefix)::BIGINT,
    COUNT(DISTINCT org_id)::BIGINT
  FROM mv_as_route_summary

  UNION ALL

  SELECT
    'mv_as_allocation_summary'::TEXT,
    COUNT(*)::BIGINT,
    COUNT(DISTINCT asn)::BIGINT,
    COUNT(DISTINCT range_start)::BIGINT,
    COUNT(DISTINCT org_id)::BIGINT
  FROM mv_as_allocation_summary;
END;
$$ LANGUAGE plpgsql;

COMMENT ON MATERIALIZED VIEW mv_as_route_summary IS
'Primary view for AS to route/prefix mapping with organization details. Combines whois_aut_num, whois_routes, and whois_organisations tables.';

COMMENT ON MATERIALIZED VIEW mv_as_allocation_summary IS
'Secondary view for AS to IP allocation mapping. Links autonomous systems to their allocated IP ranges from inetnum records.';

COMMENT ON FUNCTION refresh_whois_materialized_views IS
'Refresh all WHOIS materialized views. Use concurrent=TRUE for production refreshes to avoid blocking reads.';

COMMENT ON FUNCTION whois_view_statistics IS
'Get statistics about the WHOIS materialized views including row counts and unique entity counts.';