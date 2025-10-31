# WHOIS RIR Data Guide

## Overview

This document provides comprehensive information about WHOIS data formats, parsing requirements, and database schema mappings for all five Regional Internet Registries (RIRs). It serves as the authoritative reference for implementing and maintaining WHOIS data parsers.

## Quick Reference: RIR Comparison

| RIR | Region | Objects | File Size | Primary Types | Date Format | IP Format | ASN Format | Error Rate |
|-----|--------|---------|-----------|---------------|-------------|-----------|------------|------------|
| **LACNIC** | Latin America | 519K | 4.5 MB | inetnum, aut-num only | YYYY-MM-DD | CIDR | Plain number | 0% |
| **AFRINIC** | Africa | 427K | 9.6 MB | All types | Embedded YYYYMMDD | start - end | Plain number | 1.3% |
| **APNIC** | Asia-Pacific | Unknown | Split files | All types | RFC3339 | start - end | Plain number | 0% |
| **RIPE** | Europe | 4.7M | 350 MB | All types | RFC3339 | start - end | Plain number | 0.00002% |
| **ARIN** | North America | 158K | 4.5 MB | 90% routes | RFC3339 | CIDR | AS prefix | 0% |

## Data Sources

### Download URLs
```
LACNIC:  https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz
AFRINIC: https://ftp.afrinic.net/pub/dbase/afrinic.db.gz
APNIC:   https://ftp.apnic.net/apnic/whois/apnic.db.*.gz (split by type)
RIPE:    https://ftp.ripe.net/ripe/dbase/ripe.db.gz
ARIN:    https://ftp.arin.net/pub/rr/arin.db.gz
```

### APNIC Split Files
APNIC uniquely splits data by object type:
- `apnic.db.inetnum.gz` - IPv4 allocations
- `apnic.db.inet6num.gz` - IPv6 allocations
- `apnic.db.aut-num.gz` - AS numbers
- `apnic.db.route.gz` - IPv4 routes
- `apnic.db.route6.gz` - IPv6 routes
- `apnic.db.as-set.gz` - AS sets
- `apnic.db.mntner.gz` - Maintainer objects

## RPSL Format Specification

### Basic Structure
```
object-type: primary-key-value
attribute: value
attribute: value1
+           value2
attribute: value
# Comments start with hash
% Comments can also start with percent

object-type: another-object
attribute: value
```

### Key Parsing Rules

1. **Object Boundaries**: Blank lines separate objects
2. **Object Type**: First non-comment line (before colon)
3. **Primary Key**: Value on first line (after colon)
4. **Continuation Lines**: Start with whitespace or `+`
5. **Multi-value Attributes**: Same key appears multiple times
6. **Comments**: Lines starting with `#` or `%` are ignored
7. **Encoding**: UTF-8, occasional Latin-1 in older data

### Object Type Identification
```go
// First non-comment line format: "type: primary-key"
Examples:
inetnum:     192.0.2.0 - 192.0.2.255
inet6num:    2001:db8::/32
aut-num:     AS64512
route:       192.0.2.0/24
organisation: ORG-TEST1-RIPE
person:      TEST-HANDLE
role:        Abuse Contact
mntner:      TEST-MNT
domain:      2.0.192.in-addr.arpa
```

## Per-RIR Detailed Specifications

### LACNIC (Latin America and Caribbean)

**Characteristics:**
- Simplest dataset with only network allocations
- Clean, consistent formatting
- No parse errors in 519K objects

**Object Type Distribution:**
| Object Type | Count | Percentage |
|-------------|-------|------------|
| inetnum | 475,575 | 91.58% |
| inet6num | 29,770 | 5.73% |
| aut-num | 13,931 | 2.68% |

**Special Parsing Requirements:**
```python
# IP ranges in CIDR format
inetnum: 5.183.80/22  # Note: missing dot before /22

# Date format
created: 2010-07-28
changed: 2023-11-15

# No AS prefix on numbers
aut-num: 264668
```

### AFRINIC (Africa)

**Characteristics:**
- Most complete African registry data
- Unique date embedding in email fields
- 1.3% parse errors (mostly encoding issues)

**Object Type Distribution:**
| Object Type | Count | Percentage | Notes |
|-------------|-------|------------|-------|
| inetnum | 171,259 | 40.13% | IPv4 allocations |
| route | 116,726 | 27.35% | BGP routes |
| domain | 39,010 | 9.14% | Reverse DNS |
| inet6num | 32,493 | 7.61% | IPv6 allocations |
| mntner | 27,268 | 6.39% | Maintainer objects |
| person | 25,598 | 6.00% | Contact persons |
| organisation | 3,647 | 0.85% | LIRs/Organizations |
| Others | ~3,000 | <1% | Various types |

**Special Parsing Requirements:**
```python
# Embedded date format (last 8 chars of email)
e-mail: hostmaster@afrinic.net 20040831  # Date: 2004-08-31

# IP range format
inetnum: 41.0.0.0 - 41.0.255.255

# Extract date:
if source == "afrinic" and key == "e-mail":
    if len(value) > 8 and value[-8:].isdigit():
        date = value[-8:]  # YYYYMMDD format
        email = value[:-8].strip()
```

### APNIC (Asia-Pacific)

**Characteristics:**
- Data split across multiple files by type
- Largest IP allocation database in Asia
- Clean, well-structured data

**Object Types:** (Estimated)
- inetnum: ~2M+
- inet6num: ~300K
- aut-num: ~20K
- route/route6: ~500K
- Other types in separate files

**Special Parsing Requirements:**
```python
# RFC3339 timestamps
last-modified: 2023-11-15T04:23:12Z

# IP range format
inetnum: 1.0.0.0 - 1.0.0.255

# Standard AS format
aut-num: AS4608
```

### RIPE (Europe, Middle East, Central Asia)

**Characteristics:**
- Largest dataset (4.7M objects)
- Most diverse object types (21 types)
- Includes poetry objects (poem, poetic-form)
- Excellent data quality (1 error in 4.7M)

**Object Type Distribution (Top 10):**
| Object Type | Count | Percentage |
|-------------|-------|------------|
| inetnum | 3,081,686 | 65.55% |
| domain | 725,448 | 15.43% |
| inet6num | 322,302 | 6.86% |
| route | 266,790 | 5.67% |
| organisation | 88,284 | 1.88% |
| role | 76,392 | 1.62% |
| mntner | 48,749 | 1.04% |
| aut-num | 30,217 | 0.64% |
| route6 | 30,030 | 0.64% |
| as-set | 20,172 | 0.43% |

**Special Parsing Requirements:**
```python
# RFC3339 timestamps
created: 2002-09-25T09:52:53Z
last-modified: 2023-11-15T10:15:42Z

# IP range format
inetnum: 193.0.0.0 - 193.0.7.255

# Organisation reference
org: ORG-RIPE1-RIPE
```

### ARIN (American Registry for Internet Numbers)

**Characteristics:**
- Primarily route objects (72% of dataset)
- Uses CIDR notation for networks
- AS numbers have "AS" prefix

**Object Type Distribution:**
| Object Type | Count | Percentage | Notes |
|-------------|-------|------------|-------|
| route | 114,154 | 72.12% | IPv4 routes |
| route6 | 32,001 | 20.22% | IPv6 routes |
| as-set | 5,614 | 3.55% | AS groups |
| aut-num | 4,061 | 2.57% | AS numbers |
| route-set | 2,446 | 1.55% | Route groups |

**Special Parsing Requirements:**
```python
# AS number with prefix
aut-num: AS701

# Strip AS prefix:
if asn.startswith("AS"):
    asn = asn[2:]

# CIDR format for routes
route: 8.0.0.0/9

# RFC3339 timestamps
last-modified: 2023-11-15T15:30:00Z
```

## Database Schema Mapping

### Table Overview

| Table | Object Types | Primary Key | Purpose |
|-------|--------------|-------------|---------|
| whois_inetnum | inetnum, inet6num | (source, range_start, range_end, timestamp) | IP allocations |
| whois_aut_num | aut-num | (source, asn, timestamp) | AS numbers |
| whois_routes | route, route6 | (source, prefix, origin_asn, timestamp) | BGP routes |
| whois_organisations | organisation | (source, org_id, timestamp) | Organizations |
| whois_objects | all others | (source, object_type, object_key, timestamp) | Generic objects |

### Field Mappings

#### whois_inetnum
```sql
-- Required fields
source        TEXT        -- 'lacnic-whois', 'ripe-whois', etc.
range_start   INET        -- Start IP (INET type handles both formats)
range_end     INET        -- End IP
netname       TEXT        -- Network name
last_modified TIMESTAMPTZ -- Last modification time

-- Optional fields
country       TEXT        -- ISO country code
org_id        TEXT        -- Organisation reference
status        TEXT        -- Allocation status
descr         TEXT[]      -- Description array
admin_c       TEXT[]      -- Admin contacts
tech_c        TEXT[]      -- Tech contacts
mnt_by        TEXT[]      -- Maintainers
created       TIMESTAMPTZ -- Creation date
extra_attrs   JSONB       -- RIR-specific attributes
```

#### whois_aut_num
```sql
-- Required fields
source        TEXT        -- RIR source
asn           BIGINT      -- AS number (without 'AS' prefix)
last_modified TIMESTAMPTZ

-- Optional fields
as_name       TEXT        -- AS name
org_id        TEXT        -- Organisation
country       TEXT        -- Country
descr         TEXT[]      -- Description
admin_c       TEXT[]      -- Contacts
tech_c        TEXT[]
mnt_by        TEXT[]      -- Maintainers
import_policy JSONB       -- Import rules
export_policy JSONB       -- Export rules
created       TIMESTAMPTZ
extra_attrs   JSONB
```

#### whois_routes
```sql
-- Required fields
source        TEXT        -- RIR source
prefix        CIDR        -- Route prefix (CIDR type)
last_modified TIMESTAMPTZ

-- Optional fields
origin_asn    BIGINT      -- Origin AS
descr         TEXT[]      -- Description
mnt_by        TEXT[]      -- Maintainers
member_of     TEXT[]      -- Route-set membership
created       TIMESTAMPTZ
extra_attrs   JSONB
```

#### whois_organisations
```sql
-- Required fields
source        TEXT        -- RIR source
org_id        TEXT        -- e.g., "ORG-TEST1-RIPE"
org_name      TEXT        -- Organization name
last_modified TIMESTAMPTZ

-- Optional fields
org_type      TEXT        -- LIR, OTHER, etc.
country       TEXT        -- ISO code
address       TEXT[]      -- Address lines
email         TEXT[]      -- Email addresses
phone         TEXT[]      -- Phone numbers
admin_c       TEXT[]      -- Admin contacts
tech_c        TEXT[]      -- Tech contacts
mnt_ref       TEXT[]      -- Maintainer references
mnt_by        TEXT[]      -- Maintained by
created       TIMESTAMPTZ
extra_attrs   JSONB
```

#### whois_objects (Generic)
```sql
-- All fields required
source        TEXT        -- RIR source
object_type   TEXT        -- as-set, mntner, person, role, etc.
object_key    TEXT        -- Primary identifier
attributes    JSONB       -- All attributes as JSON
last_modified TIMESTAMPTZ
```

### Idempotency Strategy

All tables use composite UNIQUE constraints for idempotent inserts:
```sql
-- Example for routes table
UNIQUE(source, prefix, origin_asn, last_modified, timestamp)

-- Insert pattern
INSERT INTO whois_routes (...) VALUES (...)
ON CONFLICT DO NOTHING;
```

## Implementation Notes

### Batch Processing
```go
const batchSize = 500  // Optimal for memory/performance balance

// Accumulate objects in batches
batch := make([]DataType, 0, batchSize)
for obj := range objects {
    batch = append(batch, convertObject(obj))
    if len(batch) >= batchSize {
        storage.StoreBatch(ctx, batch)
        batch = batch[:0]  // Reset slice, reuse capacity
    }
}
// Flush remaining
if len(batch) > 0 {
    storage.StoreBatch(ctx, batch)
}
```

### Memory Management
- **Stream Processing**: Never load entire file into memory
- **Gzip Streaming**: Decompress on-the-fly
- **Channel Buffering**: Use buffered channels (size 100)
- **Batch Reuse**: Reset slices, maintain capacity

### Error Handling
```go
// Continue on parse errors
for {
    select {
    case err := <-errors:
        errorCount++
        if errorCount%1000 == 0 {
            log.Printf("Parse errors: %d", errorCount)
        }
        // Continue processing
    case obj := <-objects:
        // Process object
    }
}
```

### Performance Expectations

| RIR | Objects/sec | Memory Usage | Processing Time |
|-----|-------------|--------------|-----------------|
| LACNIC | 2,460 | ~30 MB | 3.5 min |
| AFRINIC | 485 | ~40 MB | 7 min |
| APNIC | 1,250 | ~35 MB | Variable |
| RIPE | 1,800 | ~50 MB | 45 min |
| ARIN | 2,143 | ~30 MB | 1.5 min |

### Common Edge Cases

1. **Missing Primary Keys**
   - Some objects lack primary keys
   - Use first attribute value as fallback

2. **Encoding Issues**
   - AFRINIC: Occasional Latin-1 encoding
   - Solution: Try UTF-8, fallback to Latin-1

3. **Date Format Variations**
   ```go
   // Try multiple formats
   formats := []string{
       time.RFC3339,      // 2006-01-02T15:04:05Z
       "2006-01-02",      // YYYY-MM-DD
       "20060102",        // YYYYMMDD
   }
   ```

4. **Token Too Long**
   - RIPE has some objects >64KB
   - Increase scanner buffer size

5. **Empty Objects**
   - Skip objects with no attributes
   - Log but don't fail

## Testing Strategy

### Unit Tests
- Test each conversion function with sample data
- Verify date parsing for each format
- Test IP range conversions
- Validate ASN normalization

### Integration Tests
1. Parse first 1000 objects from each RIR
2. Verify all object types are handled
3. Check database insertion
4. Validate idempotency

### Load Tests
- Process full LACNIC (smallest, 519K)
- Monitor memory usage
- Verify performance metrics
- Check error rates

## Maintenance Notes

### Regular Updates
- RIRs update daily
- Schedule imports during low-traffic periods
- Keep 30 days of history (TimescaleDB retention)

### Monitoring
- Track parse error rates
- Monitor processing speed
- Alert on missing object types
- Check for schema changes

### Schema Evolution
- New object types → whois_objects table
- New attributes → extra_attrs JSONB
- Backwards compatible by design

## Appendix: Sample Objects

### RIPE inetnum
```
inetnum:        192.0.2.0 - 192.0.2.255
netname:        TEST-NET-1
descr:          Test Network
country:        NL
org:            ORG-TEST1-RIPE
admin-c:        TEST-RIPE
tech-c:         TEST-RIPE
status:         ASSIGNED PA
mnt-by:         RIPE-NCC-MNT
created:        2022-01-15T10:30:00Z
last-modified:  2023-11-15T14:45:30Z
source:         RIPE
```

### ARIN route
```
route:          8.8.8.0/24
origin:         AS15169
descr:          Google Public DNS
mnt-by:         MAINT-AS15169
created:        2010-03-24T00:00:00Z
last-modified:  2023-01-10T12:00:00Z
source:         ARIN
```

### AFRINIC organisation
```
organisation:   ORG-AA1-AFRINIC
org-name:       Example Organization
org-type:       LIR
address:        123 Main Street
address:        Cape Town
address:        South Africa
country:        ZA
phone:          +27 21 555 0123
e-mail:         admin@example.co.za 20230315
admin-c:        AA1-AFRINIC
tech-c:         AA2-AFRINIC
mnt-ref:        AFRINIC-HM-MNT
mnt-by:         AFRINIC-HM-MNT
created:        2015-06-10T09:00:00Z
last-modified:  2023-03-15T11:30:00Z
source:         AFRINIC
```

---

*Last Updated: 2025-10-30*
*Version: 1.0*