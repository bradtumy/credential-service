package main

import (
    "fmt"
    "log"
    "os"
    sdk "github.com/bradtumy/credential-service/sdk-go"
)

func main() {
    issuerURL := env("ISSUER_URL", "http://localhost:8080")
    verifierURL := env("VERIFIER_URL", "http://localhost:8081")
    subjectDID := os.Getenv("ALICE_DID")
    if subjectDID == "" {
        log.Fatalf("ALICE_DID is required. Generate one via ./bin/keygen -did-only and export ALICE_DID before running.")
    }

    client := sdk.NewClient("", "")
    issued, err := client.IssueSDJWTCredential(issuerURL, sdk.SDJWTIssueRequest{
        SubjectDID: subjectDID,
        TTLSeconds: 600,
        Claims: map[string]interface{}{
            "email": "alice@example.com",
            "department": "engineering",
            "scope": "read:orders",
        },
    })
    if err != nil {
        log.Fatalf("issue sd-jwt: %v", err)
    }
    fmt.Println("SD-JWT:", issued.Credential)
    fmt.Println("Disclosures:", issued.Disclosures)

    verify, err := client.VerifySDJWT(verifierURL, issued.Credential, issued.Disclosures[:1])
    if err != nil {
        log.Fatalf("verify sd-jwt: %v", err)
    }
    fmt.Println("Partial verification active:", verify.Active)
}

func env(k, def string) string {
    v := os.Getenv(k)
    if v == "" {
        return def
    }
    return v
}
