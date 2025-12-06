# Credential Service Go SDK

A first-class Go client for issuing, verifying, and authorizing credentials with the Credential Service.

## Installation

```bash
go get github.com/bradtumy/credential-service/sdk-go
```

## Quickstart

```go
package main

import (
    "context"
    "log"

    sdk "github.com/bradtumy/credential-service/sdk-go"
)

func main() {
    client := sdk.NewLocalDevClient()

    issued, err := client.IssueVC(context.Background(), sdk.IssueRequest{
        SubjectDID: "did:example:alice",
        TTLSeconds: 600,
        Claims: map[string]any{"aud": "sample-api"},
    })
    if err != nil {
        log.Fatalf("issue failed: %v", err)
    }

    verified, err := client.Verify(context.Background(), issued.Credential)
    if err != nil {
        log.Fatalf("verify failed: %v", err)
    }
    log.Printf("valid=%v subject=%s", verified.Valid, verified.Subject)

    decision, err := client.Authorize(context.Background(), sdk.AuthorizeRequest{
        Credential:       issued.Credential,
        ExpectedAudience: "sample-api",
        WantSyntheticJWT: true,
    })
    if err != nil {
        log.Fatalf("authorize failed: %v", err)
    }
    log.Printf("allowed=%v synthetic_jwt=%s", decision.Allowed, decision.SyntheticJWT)
}
```

For end-to-end flows and service details, see the repository root `README.md` and the docs directory.
