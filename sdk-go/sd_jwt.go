package sdk

import (
  "bytes"
  "encoding/json"
  "fmt"
  "net/http"
  "time"
)

type SDJWTIssueRequest struct {
  SubjectDID  string                 `json:"subject_did"`
  TTLSeconds  int                    `json:"ttl_seconds"`
  Claims      map[string]interface{} `json:"claims"`
  Format      string                 `json:"format"` // always "sd-jwt"
}

type SDJWTIssueResponse struct {
  Credential  string   `json:"credential"`
  Disclosures []string `json:"disclosures"`
  Issuer      string   `json:"issuer,omitempty"`
  Subject     string   `json:"subject,omitempty"`
  Exp         int64    `json:"exp,omitempty"`
}

type SDJWTVerifyRequest struct {
  Credential  string   `json:"credential"`
  Format      string   `json:"format"` // "sd-jwt"
  Disclosures []string `json:"disclosures"`
}

type SDJWTVerifyResponse struct {
  Active      bool     `json:"active"`
  Issuer      string   `json:"issuer,omitempty"`
  Subject     string   `json:"subject,omitempty"`
  Exp         int64    `json:"exp,omitempty"`
  Missing     []string `json:"missing_disclosures,omitempty"`
}

// IssueSDJWTCredential issues an SD-JWT credential and returns the token plus disclosures.
// issuerBaseURL should be the base (e.g. http://localhost:8080).
func (c *Client) IssueSDJWTCredential(issuerBaseURL string, req SDJWTIssueRequest) (*SDJWTIssueResponse, error) {
  if req.Format == "" { req.Format = "sd-jwt" }
  payload, err := json.Marshal(req)
  if err != nil { return nil, err }
  url := fmt.Sprintf("%s/v1/credentials/issue", issuerBaseURL)
  httpReq, err := http.NewRequest("POST", url, bytes.NewReader(payload))
  if err != nil { return nil, err }
  httpReq.Header.Set("Content-Type", "application/json")
  resp, err := c.HTTPClient.Do(httpReq)
  if err != nil { return nil, err }
  defer resp.Body.Close()
  var out SDJWTIssueResponse
  if resp.StatusCode != http.StatusOK {
    return nil, fmt.Errorf("issue sd-jwt failed: status=%d", resp.StatusCode)
  }
  decoder := json.NewDecoder(resp.Body)
  if err := decoder.Decode(&out); err != nil { return nil, err }
  return &out, nil
}

// VerifySDJWT verifies an SD-JWT with selective disclosures.
// verifierBaseURL is typically http://localhost:8081.
func (c *Client) VerifySDJWT(verifierBaseURL string, credential string, disclosures []string) (*SDJWTVerifyResponse, error) {
  req := SDJWTVerifyRequest{Credential: credential, Format: "sd-jwt", Disclosures: disclosures}
  payload, err := json.Marshal(req)
  if err != nil { return nil, err }
  url := fmt.Sprintf("%s/v1/credentials/verify", verifierBaseURL)
  httpReq, err := http.NewRequest("POST", url, bytes.NewReader(payload))
  if err != nil { return nil, err }
  httpReq.Header.Set("Content-Type", "application/json")
  resp, err := c.HTTPClient.Do(httpReq)
  if err != nil { return nil, err }
  defer resp.Body.Close()
  var out SDJWTVerifyResponse
  if resp.StatusCode != http.StatusOK {
    return nil, fmt.Errorf("verify sd-jwt failed: status=%d", resp.StatusCode)
  }
  decoder := json.NewDecoder(resp.Body)
  if err := decoder.Decode(&out); err != nil { return nil, err }
  return &out, nil
}

// Convenience helpers returning time-to-expiry if Exp present.
func (r *SDJWTIssueResponse) TimeToExpiry() time.Duration {
  if r.Exp == 0 { return 0 }
  return time.Until(time.Unix(r.Exp, 0))
}
func (r *SDJWTVerifyResponse) TimeToExpiry() time.Duration {
  if r.Exp == 0 { return 0 }
  return time.Until(time.Unix(r.Exp, 0))
}
