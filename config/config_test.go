package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://whatscore:password@localhost:5432/whatscore?sslmode=disable")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.App.Name != "WhatsCore" {
		t.Errorf("App.Name = %q, want %q", cfg.App.Name, "WhatsCore")
	}
	if cfg.App.Env != "development" {
		t.Errorf("App.Env = %q, want development", cfg.App.Env)
	}
	if cfg.App.Port != 8080 {
		t.Errorf("App.Port = %d, want 8080", cfg.App.Port)
	}
	if cfg.App.LogLevel != "info" {
		t.Errorf("App.LogLevel = %q, want info", cfg.App.LogLevel)
	}
	if !cfg.Database.MigrateOnStartup {
		t.Error("Database.MigrateOnStartup = false, want true")
	}
	if cfg.Engine.SessionLimit != 10 {
		t.Errorf("Engine.SessionLimit = %d, want 10", cfg.Engine.SessionLimit)
	}
	if cfg.Webhook.Timeout.String() != "10s" {
		t.Errorf("Webhook.Timeout = %s, want 10s", cfg.Webhook.Timeout)
	}
	if cfg.Webhook.MaxRetries != 10 {
		t.Errorf("Webhook.MaxRetries = %d, want 10", cfg.Webhook.MaxRetries)
	}
	if cfg.Media.MaxSizeBytes != 50*1024*1024 {
		t.Errorf("Media.MaxSizeBytes = %d, want %d", cfg.Media.MaxSizeBytes, 50*1024*1024)
	}
	if !cfg.Security.APIKeyRequired {
		t.Error("Security.APIKeyRequired = false, want true")
	}
	if cfg.Addr() != ":8080" {
		t.Errorf("Addr() = %q, want :8080", cfg.Addr())
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("APP_NAME", "WhatsCore-Test")
	t.Setenv("APP_ENV", "production")
	t.Setenv("APP_PORT", "9090")
	t.Setenv("APP_LOG_LEVEL", "debug")
	t.Setenv("DATABASE_URL", "postgres://postgres:postgres@db.internal:5432/wc?sslmode=require")
	t.Setenv("DB_MIGRATE_ON_STARTUP", "false")
	t.Setenv("WHATSAPP_SESSION_LIMIT", "25")
	t.Setenv("WEBHOOK_TIMEOUT_SECONDS", "5")
	t.Setenv("WEBHOOK_MAX_RETRIES", "3")
	t.Setenv("ENCRYPTION_KEY", "a-real-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.App.Env != "production" || !cfg.IsProduction() {
		t.Errorf("App.Env = %q, IsProduction = %v", cfg.App.Env, cfg.IsProduction())
	}
	if cfg.App.Port != 9090 {
		t.Errorf("App.Port = %d, want 9090", cfg.App.Port)
	}
	if cfg.App.LogLevel != "debug" {
		t.Errorf("App.LogLevel = %q, want debug", cfg.App.LogLevel)
	}
	if cfg.Database.URL != "postgres://postgres:postgres@db.internal:5432/wc?sslmode=require" {
		t.Errorf("Database.URL = %q", cfg.Database.URL)
	}
	if cfg.Database.MigrateOnStartup {
		t.Error("Database.MigrateOnStartup = true, want false")
	}
	if cfg.Engine.SessionLimit != 25 {
		t.Errorf("Engine.SessionLimit = %d, want 25", cfg.Engine.SessionLimit)
	}
	if cfg.Webhook.Timeout.String() != "5s" {
		t.Errorf("Webhook.Timeout = %s, want 5s", cfg.Webhook.Timeout)
	}
	if cfg.Webhook.MaxRetries != 3 {
		t.Errorf("Webhook.MaxRetries = %d, want 3", cfg.Webhook.MaxRetries)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]struct {
		setup func(t *testing.T)
	}{
		"missing DATABASE_URL": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "")
			},
		},
		"invalid port": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "postgres://localhost/db")
				t.Setenv("APP_PORT", "70000")
			},
		},
		"invalid log level": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "postgres://localhost/db")
				t.Setenv("APP_LOG_LEVEL", "verbose")
			},
		},
		"invalid boolean": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "postgres://localhost/db")
				t.Setenv("API_KEY_REQUIRED", "yes-please")
			},
		},
		"production without ENCRYPTION_KEY": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "postgres://localhost/db")
				t.Setenv("APP_ENV", "production")
			},
		},
		"zero session limit": {
			setup: func(t *testing.T) {
				t.Setenv("DATABASE_URL", "postgres://localhost/db")
				t.Setenv("WHATSAPP_SESSION_LIMIT", "0")
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.setup(t)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() returned nil error, want error")
			}
		})
	}
}
