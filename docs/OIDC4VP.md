# OIDC4VP (Verifier) — Response Handling

This service now validates OpenID for Verifiable Presentations (OIDC4VP) responses in **direct_post** mode. It does **not** yet expose an authorization request creation endpoint; authorization requests must be created and stored by the verifier frontend or an upstream component. The response handler uses the stored request to validate nonce, state, and credential requirements.

## Supported response flow

* **Response Mode:** `direct_post`
* **Response Type:** `vp_token`
* **Credential Query Language:** DCQL (subset)
* **Formats:**
  * `jwt_vc_json` (W3C VC-JWT)
  * `dc+sd-jwt` (SD-JWT VC without holder binding)

## Endpoint

`POST /v1/oidc4vp/response`

`Content-Type: application/x-www-form-urlencoded`

Form parameters:

| Parameter | Required | Notes |
| --- | --- | --- |
| `state` | yes | Must match a stored authorization request. |
| `vp_token` | yes | JSON object keyed by DCQL credential query id. |

On success, the endpoint returns a JSON payload with `verified=true` and the holder DID (if provided in the presentation).

## Validation rules (summary)

* **State** must match a stored request and be unused.
* **Nonce** is required when the query requires holder binding.
* **Holder binding**:
  * For `jwt_vc_json`, the VP JWT must be signed by the holder and bound to `aud=client_id` and the request `nonce`.
  * For `dc+sd-jwt`, holder binding is **not** supported yet. Requests requiring holder binding for this format are rejected.
* **Issuer trust** is enforced via the configured trust registry.
* **Revocation checks** are enforced when `OIDC4VP_REVOCATION_STRICT=true`.

## Configuration

| Environment variable | Default | Description |
| --- | --- | --- |
| `OIDC4VP_MAX_REQUEST_SIZE` | `262144` | Maximum request body size in bytes. |
| `OIDC4VP_REVOCATION_STRICT` | `true` | Reject revoked credentials (by VC `id`/`jti`). |

## Notes

* The `dc+sd-jwt` format requires `vct_values` in the credential query metadata. The verifier checks the `vct` claim in the presented SD-JWT VC.
* For `jwt_vc_json`, `type_values` is required in the credential query metadata and is checked against the credential `type` array.
