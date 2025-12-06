package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bradtumy/credential-service/internal/crypto"
	sdk "github.com/bradtumy/credential-service/sdk/go"
)

const (
	issuerURLEnv   = "CRED_ISSUER_URL"
	verifierURLEnv = "CRED_VERIFIER_URL"

	defaultIssuerURL   = "http://localhost:8080"
	defaultVerifierURL = "http://localhost:8081"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "did":
		err = handleDID(os.Args[2:])
	case "vc":
		err = handleVC(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleDID(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing did subcommand")
		didUsage()
		return errors.New("missing did subcommand")
	}

	switch args[0] {
	case "create":
		return didCreate(args[1:])
	case "-h", "--help", "help":
		didUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "unknown did command: %s\n", args[0])
		didUsage()
		return fmt.Errorf("unknown did command: %s", args[0])
	}
}

func didCreate(args []string) error {
	fs := flag.NewFlagSet("did create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	algorithm := fs.String("alg", "EdDSA", "Key algorithm (EdDSA or ES256)")

	if err := fs.Parse(args); err != nil {
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return err
	}

	kp, err := crypto.GenerateDIDJWK(*algorithm)
	if err != nil {
		return fmt.Errorf("generate did:jwk: %w", err)
	}

	var publicJWK map[string]interface{}
	if err := json.Unmarshal(kp.PublicJWK, &publicJWK); err != nil {
		return fmt.Errorf("decode public jwk: %w", err)
	}

	output := map[string]interface{}{
		"did":             kp.DID,
		"algorithm":       kp.Algorithm,
		"public_jwk":      publicJWK,
		"private_key_pem": strings.TrimSpace(string(kp.PrivateKeyPEM)),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func handleVC(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing vc subcommand")
		vcUsage()
		return errors.New("missing vc subcommand")
	}

	switch args[0] {
	case "issue":
		return vcIssue(args[1:])
	case "verify":
		return vcVerify(args[1:])
	case "-h", "--help", "help":
		vcUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "unknown vc command: %s\n", args[0])
		vcUsage()
		return fmt.Errorf("unknown vc command: %s", args[0])
	}
}

func vcIssue(args []string) error {
	fs := flag.NewFlagSet("vc issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	subject := fs.String("subject-did", "", "Subject DID for the credential (required)")
	scopeStr := fs.String("scope", "", "Comma-separated scope values")
	ttl := fs.Int64("ttl-seconds", 300, "Credential TTL in seconds")
	issuerURL := fs.String("issuer-url", envDefault(issuerURLEnv, defaultIssuerURL), "Issuer service URL")

	if err := fs.Parse(args); err != nil {
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return err
	}

	if *subject == "" {
		return errors.New("--subject-did is required")
	}

	claims := map[string]interface{}{}
	scope := parseScope(*scopeStr)
	if len(scope) > 0 {
		claims["scope"] = scope
	}

	client := sdk.Client{BaseURL: *issuerURL}
	resp, err := client.IssueCredential(context.Background(), sdk.IssueRequest{
		SubjectDID: *subject,
		TTLSeconds: *ttl,
		Claims:     claims,
	})
	if err != nil {
		return fmt.Errorf("issue credential: %w", err)
	}

	fmt.Fprintln(os.Stdout, resp.Credential)
	return nil
}

func vcVerify(args []string) error {
	fs := flag.NewFlagSet("vc verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	credential := fs.String("credential", "", "Credential string to verify")
	credentialFile := fs.String("credential-file", "", "Path to file containing the credential")
	verifierURL := fs.String("verifier-url", envDefault(verifierURLEnv, defaultVerifierURL), "Verifier service URL")

	if err := fs.Parse(args); err != nil {
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return err
	}

	token := strings.TrimSpace(*credential)
	if token == "" && *credentialFile != "" {
		data, err := os.ReadFile(*credentialFile)
		if err != nil {
			return fmt.Errorf("read credential file: %w", err)
		}
		token = strings.TrimSpace(string(data))
	}

	if token == "" {
		return errors.New("either --credential or --credential-file must be provided")
	}

	client := sdk.Client{BaseURL: *verifierURL}
	resp, err := client.Verify(context.Background(), token)
	if err != nil {
		return fmt.Errorf("verify credential: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func usage() {
	fmt.Fprintf(os.Stderr, `idctl - credential service CLI

Usage:
  idctl did <command> [options]
  idctl vc <command> [options]

Commands:
  did create           Generate a did:jwk identifier
  vc issue             Issue a verifiable credential
  vc verify            Verify a credential
`)
}

func didUsage() {
	fmt.Fprintf(os.Stderr, `Usage: idctl did create [options]

Options:
  --alg string   Key algorithm (EdDSA or ES256). Default: EdDSA
`)
}

func vcUsage() {
	fmt.Fprintf(os.Stderr, `Usage: idctl vc <command> [options]

Commands:
  issue   Issue a verifiable credential
  verify  Verify a credential
`)
}

func envDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func parseScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Split(scope, ",")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return cleaned
}
