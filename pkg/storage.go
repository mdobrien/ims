package pkg

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// Storage provides database operations
type Storage struct {
	db *sql.DB
}

// NewStorage creates a new storage instance
func NewStorage(db *sql.DB) *Storage {
	return &Storage{db: db}
}

// DB returns the underlying database connection
func (s *Storage) DB() *sql.DB {
	return s.db
}

// TracerouteHop represents a single hop in a traceroute
type TracerouteHop struct {
	HopDstIP     *string  // Nullable for timeouts
	RTTms        *float64 // Nullable
	TTL          *int     // Nullable
	ResponseSize *int     // Nullable
	ASN          *int     // Nullable
	Timeout      bool
	ErrCode      *string  // Nullable
	ExtraData    *[]byte  // Nullable JSONB as bytes
}

// TracerouteData represents a complete traceroute for batch insertion
type TracerouteData struct {
	Source              string
	SourceMeasurementID string
	ProbeID             string
	Timestamp           time.Time
	SrcIP               string
	TargetIP            string
	Proto               string
	Hops                []TracerouteHop
}

// StoreTracerouteBatch stores multiple traceroutes in a single transaction
func (s *Storage) StoreTracerouteBatch(ctx context.Context, traces []TracerouteData) error {
	if len(traces) == 0 {
		return nil
	}

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare statement
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO traceroute_hops
			(timestamp, source, source_measurement_id, probe_id, hop_num,
			 hop_src_ip, hop_dst_ip, target_ip, proto, rtt_ms, ttl,
			 response_size, asn, timeout, err_code, extra_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (source, source_measurement_id, timestamp, hop_num)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	// Insert all hops from all traceroutes
	for _, trace := range traces {
		prevIP := trace.SrcIP
		inTimeoutSeq := false
		timeoutStartHop := 0

		for i, hop := range trace.Hops {
			hopNum := i + 1

			// Handle timeout compression (Option 2)
			if hop.Timeout {
				if !inTimeoutSeq {
					// First timeout in sequence - store it
					if err := s.insertHop(stmt, trace, hopNum, prevIP, &hop); err != nil {
						return err
					}
					timeoutStartHop = hopNum
					inTimeoutSeq = true
				}
				// Skip middle timeouts
				continue
			}

			// Exiting timeout sequence
			if inTimeoutSeq {
				// Store last timeout hop if it wasn't the one we just stored
				if hopNum-1 > timeoutStartHop {
					lastTimeoutHop := TracerouteHop{
						Timeout: true,
					}
					if err := s.insertHop(stmt, trace, hopNum-1, prevIP, &lastTimeoutHop); err != nil {
						return err
					}
				}
				inTimeoutSeq = false
			}

			// Store responding hop
			if err := s.insertHop(stmt, trace, hopNum, prevIP, &hop); err != nil {
				return err
			}

			// Update prevIP for next hop
			if hop.HopDstIP != nil && *hop.HopDstIP != "" {
				prevIP = *hop.HopDstIP
			}
		}

		// Handle trailing timeout sequence
		if inTimeoutSeq && len(trace.Hops) > timeoutStartHop {
			lastHop := len(trace.Hops)
			if lastHop > timeoutStartHop {
				lastTimeoutHop := TracerouteHop{
					Timeout: true,
				}
				if err := s.insertHop(stmt, trace, lastHop, prevIP, &lastTimeoutHop); err != nil {
					return err
				}
			}
		}
	}

	// Commit transaction
	return tx.Commit()
}

// Helper function to insert a single hop
func (s *Storage) insertHop(stmt *sql.Stmt, trace TracerouteData, hopNum int, hopSrcIP string, hop *TracerouteHop) error {
	_, err := stmt.Exec(
		trace.Timestamp,
		trace.Source,
		trace.SourceMeasurementID,
		trace.ProbeID,
		hopNum,
		hopSrcIP,
		hop.HopDstIP,
		trace.TargetIP,
		trace.Proto,
		hop.RTTms,
		hop.TTL,
		hop.ResponseSize,
		hop.ASN,
		hop.Timeout,
		hop.ErrCode,
		hop.ExtraData,
	)
	if err != nil {
		return fmt.Errorf("insert hop %d: %w", hopNum, err)
	}
	return nil
}

// UpdateModuleState tracks module execution
func (s *Storage) UpdateModuleState(ctx context.Context, moduleName string, success bool, recordsProcessed int64, errMsg string) error {
	if success {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO module_state (module_name, last_run, last_success, records_processed, last_error)
			VALUES ($1, NOW(), NOW(), $2, NULL)
			ON CONFLICT (module_name)
			DO UPDATE SET
				last_run = NOW(),
				last_success = NOW(),
				records_processed = module_state.records_processed + EXCLUDED.records_processed,
				last_error = NULL,
				updated_at = NOW()
		`, moduleName, recordsProcessed)
		return err
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO module_state (module_name, last_run, last_error)
		VALUES ($1, NOW(), $2)
		ON CONFLICT (module_name)
		DO UPDATE SET
			last_run = NOW(),
			last_error = EXCLUDED.last_error,
			updated_at = NOW()
	`, moduleName, errMsg)
	return err
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// ============================================================================
// WHOIS DATA STRUCTURES AND METHODS
// ============================================================================

// InetnumData represents an inetnum/inet6num WHOIS object
type InetnumData struct {
	Source       string
	RangeStart   string    // INET format
	RangeEnd     string    // INET format
	Netname      string
	Country      *string
	OrgID        *string
	Status       *string
	AdminC       []string
	TechC        []string
	Descr        []string
	Created      *time.Time
	LastModified time.Time
	MntBy        []string
	ExtraAttrs   map[string]interface{}
}

// AutNumData represents an aut-num WHOIS object
type AutNumData struct {
	Source         string
	ASN            int64
	ASName         string
	Descr          []string
	Country        *string
	OrgID          *string
	Status         *string
	AdminC         []string
	TechC          []string
	ImportPolicy   map[string]interface{}
	ExportPolicy   map[string]interface{}
	Created        *time.Time
	LastModified   time.Time
	MntBy          []string
	ExtraAttrs     map[string]interface{}
}

// StoreInetnumBatch stores multiple inetnum objects (idempotent)
func (s *Storage) StoreInetnumBatch(ctx context.Context, data []InetnumData) error {
	if len(data) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO whois_inetnum
			(timestamp, source, range_start, range_end, netname, country, org_id, status,
			 admin_c, tech_c, descr, created, last_modified, mnt_by, extra_attrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (source, range_start, range_end, last_modified, timestamp)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range data {
		// Use interface{} for JSONB fields: nil → SQL NULL, []byte → JSON
		var extraJSON interface{}
		if len(item.ExtraAttrs) > 0 {
			b, _ := json.Marshal(item.ExtraAttrs)
			extraJSON = b
		}

		_, err := stmt.ExecContext(ctx,
			time.Now(), // timestamp = ingestion time
			item.Source,
			item.RangeStart,
			item.RangeEnd,
			item.Netname,
			item.Country,
			item.OrgID,
			item.Status,
			pq.Array(item.AdminC),
			pq.Array(item.TechC),
			pq.Array(item.Descr),
			item.Created,
			item.LastModified,
			pq.Array(item.MntBy),
			extraJSON,
		)
		if err != nil {
			return fmt.Errorf("insert inetnum: %w", err)
		}
	}

	return tx.Commit()
}

// StoreAutNumBatch stores multiple aut-num objects (idempotent)
func (s *Storage) StoreAutNumBatch(ctx context.Context, data []AutNumData) error {
	if len(data) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO whois_aut_num
			(timestamp, source, asn, as_name, descr, country, org_id, status,
			 admin_c, tech_c, import_policy, export_policy, created, last_modified, mnt_by, extra_attrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (source, asn, last_modified, timestamp)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range data {
		// Use interface{} for JSONB fields: nil → SQL NULL, []byte → JSON
		var importJSON, exportJSON, extraJSON interface{}
		if len(item.ImportPolicy) > 0 {
			b, _ := json.Marshal(item.ImportPolicy)
			importJSON = b
		}
		if len(item.ExportPolicy) > 0 {
			b, _ := json.Marshal(item.ExportPolicy)
			exportJSON = b
		}
		if len(item.ExtraAttrs) > 0 {
			b, _ := json.Marshal(item.ExtraAttrs)
			extraJSON = b
		}

		_, err := stmt.ExecContext(ctx,
			time.Now(),
			item.Source,
			item.ASN,
			item.ASName,
			pq.Array(item.Descr),
			item.Country,
			item.OrgID,
			item.Status,
			pq.Array(item.AdminC),
			pq.Array(item.TechC),
			importJSON,
			exportJSON,
			item.Created,
			item.LastModified,
			pq.Array(item.MntBy),
			extraJSON,
		)
		if err != nil {
			return fmt.Errorf("insert aut-num: %w", err)
		}
	}

	return tx.Commit()
}

// RouteData represents a route/route6 WHOIS object
type RouteData struct {
	Source       string
	Prefix       string // CIDR notation
	OriginASN    int64
	Descr        []string
	MntBy        []string
	MemberOf     []string
	Created      *time.Time
	LastModified time.Time
	ExtraAttrs   map[string]interface{}
}

// OrgData represents an organisation WHOIS object
type OrgData struct {
	Source       string
	OrgID        string
	OrgName      string
	OrgType      *string
	Country      *string
	Address      []string
	Email        []string
	Phone        []string
	AdminC       []string
	TechC        []string
	Created      *time.Time
	LastModified time.Time
	MntRef       []string
	MntBy        []string
	ExtraAttrs   map[string]interface{}
}

// WhoisObjectData represents generic WHOIS objects (as-set, mntner, person, role, etc.)
type WhoisObjectData struct {
	Source       string
	ObjectType   string // as-set, route-set, mntner, person, role, domain, etc.
	ObjectKey    string // Primary identifier
	Attributes   map[string]interface{}
	LastModified time.Time
}

// StoreRoutesBatch stores multiple route objects (idempotent)
func (s *Storage) StoreRoutesBatch(ctx context.Context, data []RouteData) error {
	if len(data) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO whois_routes
			(timestamp, source, prefix, origin_asn, descr, mnt_by, member_of, created, last_modified, extra_attrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (source, prefix, origin_asn, last_modified, timestamp)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range data {
		// Use interface{} for JSONB fields: nil → SQL NULL, []byte → JSON
		var extraJSON interface{}
		if len(item.ExtraAttrs) > 0 {
			b, _ := json.Marshal(item.ExtraAttrs)
			extraJSON = b
		}

		_, err := stmt.ExecContext(ctx,
			time.Now(),
			item.Source,
			item.Prefix,
			item.OriginASN,
			pq.Array(item.Descr),
			pq.Array(item.MntBy),
			pq.Array(item.MemberOf),
			item.Created,
			item.LastModified,
			extraJSON,
		)
		if err != nil {
			return fmt.Errorf("insert route: %w", err)
		}
	}

	return tx.Commit()
}

// StoreOrgBatch stores multiple organisation objects (idempotent)
func (s *Storage) StoreOrgBatch(ctx context.Context, data []OrgData) error {
	if len(data) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO whois_organisations
			(timestamp, source, org_id, org_name, org_type, country, address, email, phone,
			 admin_c, tech_c, created, last_modified, mnt_ref, mnt_by, extra_attrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (source, org_id, last_modified, timestamp)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range data {
		// Use interface{} for JSONB fields: nil → SQL NULL, []byte → JSON
		var extraJSON interface{}
		if len(item.ExtraAttrs) > 0 {
			b, _ := json.Marshal(item.ExtraAttrs)
			extraJSON = b
		}

		_, err := stmt.ExecContext(ctx,
			time.Now(),
			item.Source,
			item.OrgID,
			item.OrgName,
			item.OrgType,
			item.Country,
			pq.Array(item.Address),
			pq.Array(item.Email),
			pq.Array(item.Phone),
			pq.Array(item.AdminC),
			pq.Array(item.TechC),
			item.Created,
			item.LastModified,
			pq.Array(item.MntRef),
			pq.Array(item.MntBy),
			extraJSON,
		)
		if err != nil {
			return fmt.Errorf("insert organisation: %w", err)
		}
	}

	return tx.Commit()
}

// StoreWhoisObjectsBatch stores generic WHOIS objects (as-set, mntner, person, role, etc.)
func (s *Storage) StoreWhoisObjectsBatch(ctx context.Context, data []WhoisObjectData) error {
	if len(data) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO whois_objects
			(timestamp, source, object_type, object_key, attributes, last_modified)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (source, object_type, object_key, last_modified, timestamp)
		DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, item := range data {
		// Attributes must always be valid JSON
		attrsJSON, err := json.Marshal(item.Attributes)
		if err != nil {
			return fmt.Errorf("marshal attributes: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			time.Now(),
			item.Source,
			item.ObjectType,
			item.ObjectKey,
			attrsJSON,
			item.LastModified,
		)
		if err != nil {
			return fmt.Errorf("insert whois object: %w", err)
		}
	}

	return tx.Commit()
}
