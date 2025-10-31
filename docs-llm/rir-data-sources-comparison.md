
# RIR Data Sources - Comparison and Analysis

## Overview

This document compares the different data sources available from RIRs to inform database schema design for the Internet Measurement System.

## RIPE Delegated Stats Files Comparison

### Standard Delegated File
**File:** `delegated-ripencc-20250101.bz2` (734KB)
**Records:** 160,635
**Format:** `registry|cc|type|start|value|date|status` (7 fields)

**Status Types:**
- `allocated` (132,786 - 82.7%)
- `assigned` (27,845 - 17.3%)

**Use Case:** Active allocations only

### Extended Delegated File
**File:** `delegated-ripencc-extended-20251029.bz2` (3.3MB - 4.5x larger)
**Records:** 254,502 (58% more)
**Format:** `registry|cc|type|start|value|date|status|org_uuid` (7-8 fields)

**Status Types:**
- `allocated` (135,222 - 53.1%)
- `assigned` (28,011 - 11.0%)
- `reserved` (84,879 - 33.4%) ← **Not in standard**
- `available` (6,386 - 2.5%) ← **Not in standard**

**Key Difference: 8th Field (Organization UUID)**
- Present for `allocated` and `assigned` resources (163,233 records)
- Missing for `reserved` and `available` resources (91,266 records)
- Links multiple allocations to the same organization/LIR
- Format: UUID (e.g., `7a7b6fbf-fe08-4afe-a113-57f7de5c0408`)

**Benefits of Extended File:**
1. ✅ Organization linkage - Can group allocations by LIR
2. ✅ Complete registry view - Shows available/reserved space
3. ✅ Resource exhaustion tracking - See what's left
4. ✅ Planning data - Understand future capacity

**IPv6 Impact:**
- Standard: 26,513 IPv6 records
- Extended: 111,075 IPv6 records (**83,608 are reserved!**)
- Shows massive IPv6 space reserved for future allocation

### Recommendation
**Use Extended Delegated File** for IMS because:
- Organization UUIDs enable linking related allocations
- Complete picture of resource registry
- Only 2.5MB extra compressed data
- Essential for comprehensive internet mapping

---

## WHOIS Database Dumps Comparison

### File Sizes
```
RIPE:    350MB compressed (largest - Europe/Middle East/Central Asia)
APNIC:    51MB compressed (Asia-Pacific)
AFRINIC: 6.7MB compressed (Africa)
LACNIC:  4.5MB compressed (Latin America)
```

### Format Differences

All use RPSL (Routing Policy Specification Language) but with variations:

**LACNIC (Simplest):**
- Only 2 object types in first 100K: `inetnum` (86%), `aut-num` (14%)
- Minimal attributes (9 total)
- Very clean, simple format
- No routing policy objects

**AFRINIC (Medium Complexity):**
- 17 object types
- 66 unique attributes
- Objects: inetnum (59%), domain (20%), person (14%), mntner, org, aut-num
- Includes routing objects (route, route6, as-set)

**APNIC (Structured):**
- First 100K objects: Only inetnum (suggests file is sorted by type)
- 19 attributes for inetnum
- Has geofeed, geoloc attributes (geographic enrichment)
- Uses `last-modified` instead of `created`/`changed`

**RIPE (Most Complex):**
- 7+ object types in first 100K
- 48 unique attributes
- Heavy on routing policy (import, export, mp-import, mp-export)
- Many multiline attributes (continuation lines)
- Objects: inetnum (61.5%), domain (34.8%), aut-num (2.7%), as-set, inet-rtr

### Common Object Types Across RIRs

**Core Objects (all RIRs):**
- `inetnum` - IPv4 address ranges
- `inet6num` - IPv6 address ranges
- `aut-num` - Autonomous System Numbers
- `person` - Contact persons
- `mntner` - Maintainer objects (access control)
- `organisation` - Organizations/LIRs

**RIPE/AFRINIC Specific:**
- `domain` - Reverse DNS delegations
- `route`/`route6` - Routing policy
- `as-set` - AS groupings
- `filter-set`, `route-set`, `peering-set` - Policy objects

### Common Attributes

**Always Present (100%):**
- `tech-c` - Technical contact
- `admin-c` - Administrative contact
- `mnt-by` - Maintainer
- `source` - Registry source
- `status` - Object status
- Timestamp field (`created`+`last-modified` or `changed`)

**Usually Present (>80%):**
- `country` - Country code
- `netname` - Network name (for inetnum)
- `descr` - Description
- `as-name` - AS name (for aut-num)

**Optional:**
- `org` - Organization reference
- `notify` - Email notifications
- `remarks` - Additional notes
- `mnt-lower`, `mnt-routes`, `mnt-domains` - Hierarchical maintainers
- Routing policy (`import`, `export`, `mp-import`, `mp-export`)

### Multiline Attributes

Attributes that span multiple lines (continuation starts with whitespace):
- `import`/`export` - Routing policies (heavily multiline in RIPE)
- `mp-import`/`mp-export` - Multiprotocol routing
- `descr` - Descriptions
- `remarks` - Comments
- `members` - AS set members
- `address` - Postal addresses

---

## Data Source Comparison Summary

### For Basic AS/IP Profiling
**Use: Extended Delegated Stats**
- Small files (3-4MB compressed)
- Simple pipe-delimited format
- Has organization UUIDs
- Complete resource view
- Easy to parse and ingest

### For Detailed WHOIS Information
**Use: WHOIS Database Dumps**
- Rich metadata (contacts, organizations, routing policy)
- Complex RPSL format
- Large files (especially RIPE at 350MB)
- Multiple object types to handle
- Requires sophisticated parser

### Recommended Ingestion Strategy

**Phase 1: Extended Delegated Stats**
- Quick wins - parse all 5 RIRs in minutes
- Core data: AS numbers, IP allocations, org UUIDs
- Foundation for entity relationships

**Phase 2: WHOIS Dumps (Selective)**
- Start with LACNIC (simplest, smallest)
- Extract key objects: inetnum, inet6num, aut-num, organisation
- Skip complex routing policy initially
- Focus on enrichment data (names, descriptions, contacts)

**Phase 3: Full WHOIS (If Needed)**
- Parse route/route6 objects for routing intelligence
- Extract person/mntner for contact tracking
- Process domain objects for reverse DNS mapping
- Handle routing policy attributes

---

## Schema Design Implications

### For Delegated Stats (Simple)

```sql
CREATE TABLE rir_allocations (
    registry TEXT,
    country CHAR(2),
    type TEXT,  -- ipv4, ipv6, asn
    start_value TEXT,  -- IP or ASN
    size_value BIGINT,  -- Address count or prefix length
    allocation_date DATE,
    status TEXT,  -- allocated, assigned, reserved, available
    org_uuid UUID,  -- From extended file
    source_file TEXT,
    imported_at TIMESTAMPTZ
);
```

### For WHOIS Dumps (Complex)

**Option 1: Generic Key-Value Store**
```sql
CREATE TABLE whois_objects (
    id BIGSERIAL PRIMARY KEY,
    object_type TEXT,  -- inetnum, aut-num, etc.
    primary_key TEXT,  -- IP range, ASN, etc.
    attributes JSONB,  -- All attributes as JSON
    source TEXT,  -- ripencc, apnic, etc.
    last_modified TIMESTAMPTZ,
    raw_object TEXT  -- Original RPSL text
);
```

**Option 2: Type-Specific Tables**
```sql
CREATE TABLE whois_inetnum (
    inetnum_range TEXT PRIMARY KEY,
    netname TEXT,
    country CHAR(2),
    org_id TEXT,
    status TEXT,
    admin_c TEXT[],
    tech_c TEXT[],
    ...
);

CREATE TABLE whois_aut_num (
    asn BIGINT PRIMARY KEY,
    as_name TEXT,
    org_id TEXT,
    status TEXT,
    import_policy JSONB,
    export_policy JSONB,
    ...
);
```

**Recommendation:** Start with Option 1 (generic) for flexibility, migrate to Option 2 for performance if needed.

---

## Summary Answer to Original Question

**Q: What is delegated-ripencc-extended file and how is it different?**

**A:** The extended file includes:
1. **Organization UUIDs** (8th field) - Links allocations to LIRs
2. **Reserved/Available resources** - Shows future capacity, not just active
3. **4x more IPv6 records** - Includes massive reserved IPv6 space
4. **Same format** - Just adds optional 8th field

**Use extended file for comprehensive internet mapping** - the UUID linkage and complete registry view are worth the 2.5MB extra data.

---

## How to Refresh Data Sources

### Download Delegated Stats Files

**RIPE Extended:**
```bash
curl -o data/ripe/delegated-ripencc-extended-$(date +%Y%m%d).bz2 \
  https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest.bz2

# Analyze
python3 scratch/rir_analyzer.py data/ripe/delegated-ripencc-extended-*.bz2
```

**ARIN Extended:**
```bash
curl -o data/ripe/delegated-arin-extended-$(date +%Y%m%d) \
  https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-$(date +%Y%m%d)

# Analyze (no compression, use text mode)
python3 scratch/rir_analyzer.py data/ripe/delegated-arin-extended-*
```

**APNIC, LACNIC, AFRINIC:**
```bash
# APNIC
curl -o data/ripe/delegated-apnic-extended-latest.bz2 \
  https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest

# LACNIC
curl -o data/ripe/delegated-lacnic-extended-latest.bz2 \
  https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest

# AFRINIC
curl -o data/ripe/delegated-afrinic-extended-latest.bz2 \
  https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest
```

### Download WHOIS Database Dumps

**All 5 RIRs:**
```bash
# Create directories
mkdir -p data/whois/{ripe,apnic,lacnic,afrinic,arin}

# RIPE (350MB - takes ~30 seconds)
curl -o data/whois/ripe/ripe.db.gz \
  https://ftp.ripe.net/ripe/dbase/ripe.db.gz

# APNIC (51MB)
curl -o data/whois/apnic/whois.apnic.db.gz \
  https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz

# LACNIC (4.5MB)
curl -o data/whois/lacnic/lacnic.db.gz \
  https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz

# AFRINIC (6.7MB)
curl -o data/whois/afrinic/afrinic.db.gz \
  https://ftp.afrinic.net/pub/dbase/afrinic.db.gz

# ARIN (4.6MB)
curl -o data/whois/arin/arin.db.gz \
  https://ftp.arin.net/pub/rr/arin.db.gz
```

### Analyze WHOIS Dumps

**Run analyzer on each RIR:**
```bash
# Analyze all RIRs (can run in parallel)
python3 scratch/whois_analyzer.py data/whois/lacnic/lacnic.db.gz &
python3 scratch/whois_analyzer.py data/whois/arin/arin.db.gz &
python3 scratch/whois_analyzer.py data/whois/afrinic/afrinic.db.gz &
python3 scratch/whois_analyzer.py data/whois/apnic/whois.apnic.db.gz &
python3 scratch/whois_analyzer.py data/whois/ripe/ripe.db.gz &  # This one takes 3-5 min

wait  # Wait for all to complete
```

**Output for each RIR:**
- `data/whois/<rir>/schema_analysis.json` - Complete analysis
- `data/whois/<rir>/schema_report.txt` - Human-readable report

### Analyzer Scripts

**For Delegated Stats:**
- **Script:** `scratch/rir_analyzer.py`
- **Format:** Pipe-delimited text
- **Analysis:** Records by type, country distribution, IPv4 block sizes, IPv6 prefixes, temporal patterns

**For WHOIS Dumps:**
- **Script:** `scratch/whois_analyzer.py`
- **Format:** RPSL (attribute: value)
- **Analysis:** Object types, attribute presence, multiline attributes, sample objects

### Quick Refresh All Data

**Complete download and analysis:**
```bash
#!/bin/bash
# Download and analyze all RIR data sources

# Delegated stats (RIPE only for now)
curl -o data/ripe/delegated-ripencc-extended-latest.bz2 \
  https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest.bz2
python3 scratch/rir_analyzer.py data/ripe/delegated-ripencc-extended-latest.bz2

# WHOIS dumps (all 5 RIRs)
mkdir -p data/whois/{ripe,apnic,lacnic,afrinic,arin}

curl -o data/whois/lacnic/lacnic.db.gz https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz &
curl -o data/whois/arin/arin.db.gz https://ftp.arin.net/pub/rr/arin.db.gz &
curl -o data/whois/afrinic/afrinic.db.gz https://ftp.afrinic.net/pub/dbase/afrinic.db.gz &
curl -o data/whois/apnic/whois.apnic.db.gz https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz &
curl -o data/whois/ripe/ripe.db.gz https://ftp.ripe.net/ripe/dbase/ripe.db.gz &

wait

# Analyze all in parallel
python3 scratch/whois_analyzer.py data/whois/lacnic/lacnic.db.gz &
python3 scratch/whois_analyzer.py data/whois/arin/arin.db.gz &
python3 scratch/whois_analyzer.py data/whois/afrinic/afrinic.db.gz &
python3 scratch/whois_analyzer.py data/whois/apnic/whois.apnic.db.gz &
python3 scratch/whois_analyzer.py data/whois/ripe/ripe.db.gz &

wait

echo "All RIR data downloaded and analyzed!"
ls -lh data/whois/*/*.{json,txt}
```

### Data Refresh Schedule

**Delegated Stats:**
- Update frequency: Daily
- New files published: ~2am UTC each day
- Size: ~15-20MB total (all 5 RIRs)

**WHOIS Dumps:**
- Update frequency: Daily
- File updates: Varies by RIR (typically daily)
- Size: ~420MB total compressed (all 5 RIRs)

### Analysis Reports Location

After running analyzers, find reports at:
```
data/ripe/schema_analysis.json       # Delegated stats analysis
data/ripe/schema_report.txt

data/whois/ripe/schema_analysis.json # WHOIS analysis
data/whois/ripe/schema_report.txt
data/whois/apnic/schema_analysis.json
data/whois/apnic/schema_report.txt
data/whois/lacnic/schema_analysis.json
data/whois/lacnic/schema_report.txt
data/whois/afrinic/schema_analysis.json
data/whois/afrinic/schema_report.txt
data/whois/arin/schema_analysis.json
data/whois/arin/schema_report.txt
```

### Verify Downloads

```bash
# Check all files downloaded correctly
ls -lh data/ripe/*.bz2
ls -lh data/whois/*/*.gz

# Quick object counts
echo "=== RIPE ===" && gunzip -c data/whois/ripe/ripe.db.gz | grep -c "^aut-num:"
echo "=== APNIC ===" && gunzip -c data/whois/apnic/whois.apnic.db.gz | grep -c "^inetnum:"
echo "=== LACNIC ===" && gunzip -c data/whois/lacnic/lacnic.db.gz | grep -c "^aut-num:"
echo "=== AFRINIC ===" && gunzip -c data/whois/afrinic/afrinic.db.gz | grep -c "^route:"
echo "=== ARIN ===" && gunzip -c data/whois/arin/arin.db.gz | grep -c "^route:"
```