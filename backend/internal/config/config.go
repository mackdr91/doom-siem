/*
Author: Domonick Mack
Date: 2026-11-16
Description: Configuration loader and validator for the Doom SIEM Go backend engine.
*/

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the runtime configuration for the Doom SIEM backend service.
type Config struct {
	Environment        string
	Version            string
	HTTPPort           int
	SyslogUDPPort      int
	SyslogTCPPort      int
	PostgresDSN        string
	ClickHouseHTTPURL  string
	ClickHouseUser     string
	ClickHousePassword string
	ClickHouseDB       string
	RedisAddr          string
	CORSAllowedOrigins []string
	AIEnabled          bool
	NVDAPIKey          string
}

// Load reads environment variables and returns a validated Config struct.
func Load() (*Config, error) {
	httpPort, err := getEnvInt("BACKEND_PORT", getEnvIntFallback("PORT", 8080))
	if err != nil {
		return nil, fmt.Errorf("invalid BACKEND_PORT: %w", err)
	}

	syslogUDPPort, err := getEnvInt("SYSLOG_UDP_PORT", 5514)
	if err != nil {
		return nil, fmt.Errorf("invalid SYSLOG_UDP_PORT: %w", err)
	}

	syslogTCPPort, err := getEnvInt("SYSLOG_TCP_PORT", 5514)
	if err != nil {
		return nil, fmt.Errorf("invalid SYSLOG_TCP_PORT: %w", err)
	}

	rawOrigins := getEnvString("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
	origins := make([]string, 0)
	for _, origin := range strings.Split(rawOrigins, ",") {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			origins = append(origins, trimmed)
		}
	}

	geminiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))

	cfg := &Config{
		Environment:        getEnvString("DOOM_ENV", "development"),
		Version:            getEnvString("DOOM_VERSION", "1.0.0-release"),
		HTTPPort:           httpPort,
		SyslogUDPPort:      syslogUDPPort,
		SyslogTCPPort:      syslogTCPPort,
		PostgresDSN:        getEnvString("POSTGRES_DSN", "postgres://doom_admin:doom_secret_pass@localhost:5432/doom_siem?sslmode=disable"),
		ClickHouseHTTPURL:  getEnvString("CLICKHOUSE_HTTP_URL", "http://localhost:8123"),
		ClickHouseUser:     getEnvString("CLICKHOUSE_USER", "doom_ch"),
		ClickHousePassword: getEnvString("CLICKHOUSE_PASSWORD", "doom_ch_secret"),
		ClickHouseDB:       getEnvString("CLICKHOUSE_DB", "doom_telemetry"),
		RedisAddr:          getEnvString("REDIS_ADDR", "localhost:6379"),
		CORSAllowedOrigins: origins,
		AIEnabled:          geminiKey != "",
		NVDAPIKey:          strings.TrimSpace(os.Getenv("NVD_API_KEY")),
	}

	return cfg, nil
}

func getEnvString(key, fallback string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}

func getEnvIntFallback(key string, fallback int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func getEnvInt(key string, fallback int) (int, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(val)
	if err != nil || parsed <= 0 || parsed > 65535 {
		return 0, fmt.Errorf("port value %q must be an integer between 1 and 65535", val)
	}
	return parsed, nil
}
