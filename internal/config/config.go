package config

import (
	"os"
	"strconv"
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
	TenancyMode     string
	LogLevel        string
}

// LoadIssuerConfigFromEnv loads issuer configuration from environment variables.
func LoadIssuerConfigFromEnv() IssuerConfig {
	return IssuerConfig{
		HTTPPort:        getenv("ISSUER_HTTP_PORT", "8080"),
		DefaultTenantID: getenv("DEFAULT_TENANT_ID", "default-tenant"),
		TenancyMode:     getenv("TENANCY_MODE", "single"),
		LogLevel:        getenv("ISSUER_LOG_LEVEL", "info"),
	}
}

// VerifierConfig holds configuration for the verifier service.
type VerifierConfig struct {
	HTTPPort           string
	DefaultTenantID    string
	DB_DSN             string
	UseDBTrustRegistry bool
	TenancyMode        string
	LogLevel           string
	GatewayCache       bool
	RateLimitEnabled   bool
	RedisAddr          string
	RedisPassword      string
	RedisDB            int
}

// LoadVerifierConfigFromEnv loads verifier configuration from environment variables.
func LoadVerifierConfigFromEnv() VerifierConfig {
	return VerifierConfig{
		HTTPPort:           getenv("VERIFIER_HTTP_PORT", "8081"),
		DefaultTenantID:    getenv("DEFAULT_TENANT_ID", "default-tenant"),
		DB_DSN:             getenv("VERIFIER_DB_DSN", ""),
		UseDBTrustRegistry: getenv("VERIFIER_USE_DB_TRUST_REGISTRY", "false") == "true",
		TenancyMode:        getenv("TENANCY_MODE", "single"),
		LogLevel:           getenv("VERIFIER_LOG_LEVEL", "info"),
		GatewayCache:       getenv("GATEWAY_CACHE_ENABLED", "false") == "true",
		RateLimitEnabled:   getenv("RATELIMIT_ENABLED", "false") == "true",
		RedisAddr:          getenv("REDIS_ADDR", ""),
		RedisPassword:      getenv("REDIS_PASSWORD", ""),
		RedisDB:            getenvInt("REDIS_DB", 0),
	}
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
