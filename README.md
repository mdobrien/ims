# Internet Measurement System (IMS)

Scalable system for collecting and analyzing internet measurement data from multiple sources.

## Quick Start

### Prerequisites
- Docker and Docker Compose
- ~3GB free disk space for first file

### Run the Skeleton

```bash
# Build and start services
docker-compose up --build

# The application will:
# 1. Start TimescaleDB
# 2. Create database schema automatically
# 3. Download RIPE Atlas traceroute file for yesterday
# 4. Parse and store traceroute hops
# 5. Display summary statistics
# 6. Exit
```

### Verify Data

```bash
# Connect to database
docker exec -it ims-timescaledb psql -U ims_user -d ims

# Check data
SELECT COUNT(*) FROM traceroute_hops;
SELECT * FROM module_status;
SELECT * FROM traceroute_paths LIMIT 5;

# Exit
\q
```

### Clean Up

```bash
# Stop and remove containers
docker-compose down

# Remove all data (including database)
docker-compose down -v
```

## Current Status

**Skeleton Implementation:**
- ✅ Processes first RIPE Atlas traceroute file (traceroute-YYYY-MM-DDT0000.bz2)
- ✅ Stores ~10K traceroutes from the file
- ✅ Idempotent storage (safe to re-run)
- ✅ TimescaleDB with auto-compression and retention

**Not Yet Implemented:**
- Process all 24 hourly files
- Retry logic and error handling
- ASN lookup (asn field is NULL)
- Other measurement types (ping, DNS, BGP)
- Daemon mode with scheduler
- Monitoring and metrics

## Project Structure

```
/cmd/ims/main.go              # Main application
/pkg/
  ├── module.go               # Module interface
  ├── storage.go              # Database operations
  └── modules/
      └── atlas_traceroute.go # RIPE Atlas traceroute module
/schema.sql                   # Database schema
/docker-compose.yml           # Docker services
/Dockerfile                   # App container
/config.json                  # Configuration
```

## Architecture

See `/docs-llm/architecture.md` for full architecture details.

### Key Design Decisions

1. **Row-per-hop schema**: Scalable to 100M+ traceroutes
2. **Hybrid ID approach**: Auto-increment + natural source IDs for idempotency
3. **TimescaleDB**: Automatic partitioning, compression, and retention
4. **Simple modules**: Each data source is a single file
5. **Docker-first**: Easy deployment and testing

## Configuration

Edit `config.json` to customize:

```json
{
  "database": {
    "host": "timescaledb",
    "max_connections": 10
  },
  "modules": {
    "atlas-traceroute": {
      "enabled": true,
      "process_first_file_only": true  // Set to false to process all 24 files
    }
  }
}
```

## Development

### Run Locally (without Docker)

```bash
# Start just the database
docker-compose up timescaledb

# Update config.json to use localhost
# Then run the app
go run cmd/ims/main.go
```

### Add Dependencies

```bash
go get <package>
go mod tidy
```

### Rebuild Container

```bash
docker-compose build app
docker-compose up app
```

## Next Steps

1. Process all 24 hourly files instead of just first one
2. Add retry logic for failed downloads
3. Integrate ASN lookup for hop IPs
4. Add ping, DNS, and other Atlas measurement types
5. Implement daemon mode with scheduler
6. Add Prometheus metrics
