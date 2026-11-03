# Innerva Go SDK

Go server SDK for the Innerva Grant Protocol (IGP) v0.1: ES256 HTTP message
signatures with a durable P-256 proof key, the access-request and browser
interaction flow, capability rotation and revocation, and streaming inference
with typed accounting. Standard library only — no third-party dependencies.

> **Read-only mirror.** This repository is published automatically from the
> Innerva source repository on each SDK release; pull requests are not merged
> here. Report bugs and ask questions in
> [this repository's issues](https://github.com/Redwood-Labs-US/innerva-client-go/issues)
> or at support@innerva.net.

- API reference: <https://innerva.net/docs/api>
- OpenAPI contract: <https://innerva.net/openapi.yaml> (every deployment serves
  its own at `/openapi.yaml`)

## Install

```sh
go get github.com/Redwood-Labs-US/innerva-client-go@v0.1.0
```

The package name is `innerva` — the last element of the import path differs
from it — so import it with an explicit name for readability:

```go
import innerva "github.com/Redwood-Labs-US/innerva-client-go"
```

Requires Go 1.22+. A running Innerva server also serves this SDK as a tarball
matching its deployed protocol version: `curl -fO https://innerva.net/sdk/go.tar.gz`.

## Usage

```go
client, err := innerva.Open(innerva.Config{
	BaseURL:      "https://innerva.net",
	ProofKeyPath: "/var/lib/myapp/innerva-proof-key.pem", // created on first run, mode 0600
	DisplayName:  "My App",
	DisplayURI:   "https://myapp.example",
	CallbackURI:  "https://myapp.example/innerva/callback",
})
if err != nil {
	return err
}

// 1. Request access and send the customer to the interaction page.
pending, err := client.CreateAccess(ctx, innerva.RequestOptions{IdempotencyKey: "order-42"})
// persist pending, then redirect the browser to pending.InteractionURI

// 2. On the callback, validate the binding and obtain a capability.
capability, err := client.Continue(ctx, pending, interactRef, callbackHash)

// 3. Run inference. The SDK refreshes an expiring capability before sending
// and never retries a started stream (streamed content is not retained).
result, err := client.Infer(ctx, &capability, "Hello!", 256, "operation-1")
fmt.Println(result.Status, result.Output, "charged:", result.CreditsCharged)
```

`result.Status` is `completed` or `incomplete`. An `incomplete` result with
`CreditsCharged == 0` and empty output is the uncharged no-output case:
retrying is a new operation and may again produce no output.

Proof-key files are interchangeable with the Python and Swift SDKs (SEC1
`EC PRIVATE KEY` PEM).

## Tests

```sh
go test ./...
```

The tests replay the shared conformance vectors in `conformance/vectors`
(signing, hashing, and stream cases generated from the server's reference
implementation), so the signing code here is pinned byte for byte to what an
Innerva deployment verifies.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
