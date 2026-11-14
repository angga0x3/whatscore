// Package config loads WhatsCore configuration from environment variables.
//
// All configuration is provided through environment variables so the same
// binary works unchanged in Docker, bare metal, and CI environments.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the root configuration object for WhatsCore.
type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Engine   EngineConfig
	Media    MediaConfig
	Webhook  WebhookConfig
	Security SecurityConfig
}

// AppConfig holds application level settings.
type AppConfig struct {
	Name     string
	Env      string
	Port     int
	LogLevel string
}

// Addr returns the listen address for the HTTP server (e.g. ":8080").
func (c Config) Addr() string {
	return ":" + strconv.Itoa(c.App.Port)
}

// IsProduction reports whether the application runs with production settings.
func (c Config) IsProduction() bool {
	return c.App.Env == "production"
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL              string
	MigrateOnStartup bool
}

// EngineConfig holds WhatsApp engine settings.
type EngineConfig struct {
	Name         string
	SessionLimit int
}

// MediaConfig holds media storage settings.
type MediaConfig struct {
	Storage      string
	Path         string
	MaxSizeMB    int
	MaxSizeBytes int64
}

// WebhookConfig holds webhook delivery settings.
type WebhookConfig struct {
	Timeout    time.Duration
	MaxRetries int
}

// SecurityConfig holds security related settings.
type SecurityConfig struct {
	APIKeyRequired bool
	EncryptionKey  string
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{}

	var err error
	if cfg.App.Name, err = envString("APP_NAME", "WhatsCore"); err != nil {
		return nil, err
	}
	if cfg.App.Env, err = envString("APP_ENV", "development"); err != nil {
		return nil, err
	}
	if cfg.App.Port, err = envInt("APP_PORT", 8080, 1, 65535); err != nil {
		return nil, err
	}
	if cfg.App.LogLevel, err = envOneOf("APP_LOG_LEVEL", "info", "debug", "info", "warn", "error"); err != nil {
		return nil, err
	}

	if cfg.Database.URL, err = envString("DATABASE_URL", ""); err != nil {
		return nil, err
	}
	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required (e.g. postgres://whatscore:password@localhost:5432/whatscore?sslmode=disable)")
	}
	if cfg.Database.MigrateOnStartup, err = envBool("DB_MIGRATE_ON_STARTUP", true); err != nil {
		return nil, err
	}

	if cfg.Engine.Name, err = envString("WHATSAPP_ENGINE", "whatsmeow"); err != nil {
		return nil, err
	}
	if cfg.Engine.SessionLimit, err = envInt("WHATSAPP_SESSION_LIMIT", 10, 1, 1_000_000); err != nil {
		return nil, err
	}

	if cfg.Media.Storage, err = envString("MEDIA_STORAGE", "local"); err != nil {
		return nil, err
	}
	if cfg.Media.Path, err = envString("MEDIA_PATH", "./storage/media"); err != nil {
		return nil, err
	}
	if cfg.Media.MaxSizeMB, err = envInt("MEDIA_MAX_SIZE_MB", 50, 1, 10240); err != nil {
		return nil, err
	}
	cfg.Media.MaxSizeBytes = int64(cfg.Media.MaxSizeMB) * 1024 * 1024

	var webhookTimeout int
	if webhookTimeout, err = envInt("WEBHOOK_TIMEOUT_SECONDS", 10, 1, 600); err != nil {
		return nil, err
	}
	cfg.Webhook.Timeout = time.Duration(webhookTimeout) * time.Second
	if cfg.Webhook.MaxRetries, err = envInt("WEBHOOK_MAX_RETRIES", 10, 0, 100); err != nil {
		return nil, err
	}

	if cfg.Security.APIKeyRequired, err = envBool("API_KEY_REQUIRED", true); err != nil {
		return nil, err
	}
	if cfg.Security.EncryptionKey, err = envString("ENCRYPTION_KEY", ""); err != nil {
		return nil, err
	}

	if cfg.IsProduction() && cfg.Security.EncryptionKey == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be set when APP_ENV=production; generate one with `openssl rand -base64 32`")
	}

	return cfg, nil
}

func envString(key, fallback string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	return v, nil
}

func envInt(key string, fallback, minVal, maxVal int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: expected integer, got %q", key, raw)
	}
	if v < minVal || v > maxVal {
		return 0, fmt.Errorf("%s: %d is out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return v, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s: expected boolean, got %q", key, raw)
	}
	return v, nil
}

func envOneOf(key, fallback string, allowed ...string) (string, error) {
	v, err := envString(key, fallback)
	if err != nil {
		return "", err
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("%s: %q must be one of %s", key, v, strings.Join(allowed, ", "))
}
