package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/domain"
	"github.com/bradtumy/credential-service/internal/issuer"
)

func main() {
	cfg := config.Load()

	baseSchema, err := domain.LoadBaseSchema(cfg.BaseSchemaPath)
	if err != nil {
		log.Fatalf("Error loading base schema: %v", err)
	}

	ctx := context.Background()
	db := connectDB(ctx, cfg.DatabaseURL)

	svc := issuer.NewService(cfg, db, nil)
	svc.BaseSchema = baseSchema

	go svc.StartCredentialIssuanceWorker(ctx)

	router := issuer.Router(svc)

	log.Printf("Credential issuer service running on port %s...", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, router))
}

func connectDB(ctx context.Context, url string) *pgxpool.Pool {
	if url == "" {
		log.Println("DATABASE_URL not provided; database operations disabled")
		return nil
	}

	db, err := pgxpool.Connect(ctx, url)
	if err != nil {
		log.Printf("Unable to connect to database: %v", err)
		return nil
	}

	return db
}

// ensure configs directory exists for local runs
func init() {
	_ = os.MkdirAll("configs", 0o755)
}
