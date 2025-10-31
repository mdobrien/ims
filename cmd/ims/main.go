package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nerdish/ims/pkg"
	"github.com/nerdish/ims/pkg/modules"

	_ "github.com/lib/pq"
)

type Config struct {
	Database DatabaseConfig            `json:"database"`
	Modules  map[string]ModuleConfig   `json:"modules"`
}

type DatabaseConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	User           string `json:"user"`
	Password       string `json:"password"`
	MaxConnections int    `json:"max_connections"`
}

type ModuleConfig struct {
	Enabled            bool   `json:"enabled"`
	BaseURL            string `json:"base_url"`
	DownloadPath       string `json:"download_path"`
	ProcessFirstOnly   bool   `json:"process_first_file_only"`
	TestDate           string `json:"test_date"`
}

func main() {
	log.Println("Starting Internet Measurement System...")

	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database with retry
	db, err := connectWithRetry(config.Database, 30*time.Second)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("Connected to database successfully")

	// Initialize storage
	storage := pkg.NewStorage(db)

	// Create context
	ctx := context.Background()

	// Register and run modules
	var modulesToRun []pkg.Module

	// Atlas traceroute module
	if atlasConfig, ok := config.Modules["atlas-traceroute"]; ok && atlasConfig.Enabled {
		atlasModule := modules.NewAtlasTraceroute(
			storage,
			atlasConfig.BaseURL,
			atlasConfig.DownloadPath,
			atlasConfig.ProcessFirstOnly,
			atlasConfig.TestDate,
		)
		modulesToRun = append(modulesToRun, atlasModule)
	}

	// LACNIC WHOIS module
	if cfg, ok := config.Modules["whois-lacnic"]; ok && cfg.Enabled {
		lacnicModule := modules.NewWhoisLACNIC(storage)
		modulesToRun = append(modulesToRun, lacnicModule)
	}

	// AFRINIC WHOIS module
	if cfg, ok := config.Modules["whois-afrinic"]; ok && cfg.Enabled {
		afrinicModule := modules.NewWhoisAFRINIC(storage)
		modulesToRun = append(modulesToRun, afrinicModule)
	}

	// APNIC WHOIS module
	if cfg, ok := config.Modules["whois-apnic"]; ok && cfg.Enabled {
		apnicModule := modules.NewWhoisAPNIC(storage)
		modulesToRun = append(modulesToRun, apnicModule)
	}

	// RIPE WHOIS module
	if cfg, ok := config.Modules["whois-ripe"]; ok && cfg.Enabled {
		ripeModule := modules.NewWhoisRIPE(storage)
		modulesToRun = append(modulesToRun, ripeModule)
	}

	// ARIN WHOIS module
	if cfg, ok := config.Modules["whois-arin"]; ok && cfg.Enabled {
		arinModule := modules.NewWhoisARIN(storage)
		modulesToRun = append(modulesToRun, arinModule)
	}

	if len(modulesToRun) == 0 {
		log.Fatal("No modules enabled in config")
	}

	// Run all enabled modules
	for _, module := range modulesToRun {
		log.Printf("Running module: %s", module.Name())

		start := time.Now()
		if err := module.Process(ctx); err != nil {
			log.Printf("Module %s failed: %v", module.Name(), err)
			storage.UpdateModuleState(ctx, module.Name(), false, 0, err.Error())
			continue
		}

		log.Printf("Module %s completed successfully in %v", module.Name(), time.Since(start))
	}

	// Query some results to verify
	if err := queryResults(db); err != nil {
		log.Printf("Warning: failed to query results: %v", err)
	}

	log.Println("Internet Measurement System completed successfully")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &config, nil
}

func connectWithRetry(cfg DatabaseConfig, maxWait time.Duration) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		getEnvOrDefault("DATABASE_HOST", cfg.Host),
		cfg.Port,
		getEnvOrDefault("DATABASE_USER", cfg.User),
		getEnvOrDefault("DATABASE_PASSWORD", cfg.Password),
		getEnvOrDefault("DATABASE_NAME", cfg.Database),
	)

	start := time.Now()
	for {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("open database: %w", err)
		}

		// Set connection pool settings
		db.SetMaxOpenConns(cfg.MaxConnections)
		db.SetMaxIdleConns(cfg.MaxConnections / 2)
		db.SetConnMaxLifetime(time.Hour)

		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()

		if err == nil {
			return db, nil
		}

		db.Close()

		if time.Since(start) >= maxWait {
			return nil, fmt.Errorf("failed to connect after %v: %w", maxWait, err)
		}

		log.Printf("Waiting for database to be ready... (%v)", time.Since(start))
		time.Sleep(2 * time.Second)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func queryResults(db *sql.DB) error {
	// Count total hops
	var count int64
	err := db.QueryRow("SELECT COUNT(*) FROM traceroute_hops").Scan(&count)
	if err != nil {
		return err
	}
	log.Printf("Total hops in database: %d", count)

	// Count unique traceroutes
	var traceCount int64
	err = db.QueryRow(`
		SELECT COUNT(DISTINCT (source, source_measurement_id))
		FROM traceroute_hops
	`).Scan(&traceCount)
	if err != nil {
		return err
	}
	log.Printf("Total unique traceroutes: %d", traceCount)

	// Sample a few traceroutes
	rows, err := db.Query(`
		SELECT source, source_measurement_id, target_ip, COUNT(*) as hop_count
		FROM traceroute_hops
		GROUP BY source, source_measurement_id, target_ip
		LIMIT 5
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	log.Println("Sample traceroutes:")
	for rows.Next() {
		var source, measurementID, targetIP string
		var hopCount int
		if err := rows.Scan(&source, &measurementID, &targetIP, &hopCount); err != nil {
			return err
		}
		log.Printf("  %s %s -> %s (%d hops)", source, measurementID, targetIP, hopCount)
	}

	return rows.Err()
}
