package config

import (
	"os"
)

// Config holds application configuration loaded from environment variables.
type Config struct {
	DatabaseURL    string
	RabbitMQHost   string
	RabbitMQPort   string
	RabbitMQUser   string
	RabbitMQPass   string
	ResolverURL    string
	BaseSchemaPath string
	HTTPPort       string
}

// Load reads environment variables and returns a Config with defaults applied.
func Load() Config {
	return Config{
		DatabaseURL:    getenv("DATABASE_URL", ""),
		RabbitMQHost:   getenv("RABBITMQ_HOST", "rabbitmq"),
		RabbitMQPort:   getenv("RABBITMQ_PORT", "5672"),
		RabbitMQUser:   getenv("RABBITMQ_USER", "guest"),
		RabbitMQPass:   getenv("RABBITMQ_PASS", "guest"),
		ResolverURL:    getenv("RESOLVER_URL", "http://resolver-service:8080/v1/dids/resolver"),
		BaseSchemaPath: getenv("BASE_SCHEMA_PATH", "configs/base-schema.json"),
		HTTPPort:       getenv("HTTP_PORT", "8080"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// IssuerConfig holds configuration for the issuer service.
type IssuerConfig struct {
	HTTPPort        string
	DefaultTenantID string
}

// LoadIssuerConfigFromEnv loads issuer configuration from environment variables.
func LoadIssuerConfigFromEnv() IssuerConfig {
	return IssuerConfig{
		HTTPPort:        getenv("ISSUER_HTTP_PORT", "8080"),
		DefaultTenantID: getenv("DEFAULT_TENANT_ID", "default-tenant"),
	}
}
