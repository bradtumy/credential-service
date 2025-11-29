package main

import (
	"log"
	"net/http"

	"github.com/bradtumy/credential-service/internal/config"
	"github.com/bradtumy/credential-service/internal/verifier"
)

func main() {
	cfg := config.Load()

	router := verifier.Router()

	log.Printf("Verifier service running on port %s...", cfg.HTTPPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HTTPPort, router))
}
