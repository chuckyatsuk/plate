# The Plate contract

`openapi.yaml` is the source of truth for Plate's HTTP API. **Both sides are
generated from it** — the Go service and every caller — so a change to the shape
of the API becomes a compile error on both ends rather than a `200` that is
quietly wrong. That drift is the recurring bug class this project exists to
escape (see the spec, §6), and it is why the contract is written before the
service.

## What's in here

| File | Purpose |
|---|---|
| `openapi.yaml` | OpenAPI 3.1 description of the full v1 surface. |
| `redocly.yaml` | Lint config. Four recommended-ruleset warnings are turned off *explicitly, with reasons* so a real new warning stands out. |

## Design rules the contract holds

- **Closed enums** for `intent` and refusal `reason` — a caller cannot invent an
  intent, and a new media type cannot silently opt into a metered delivery path.
- **`additionalProperties: false`** on every object schema; no bare `object`.
- **Required fields marked required.**
- **The account is a token claim, never a parameter.** There is no `account`
  query or path parameter anywhere; isolation is checked against the bearer
  token's `account` claim (spec Q3.A).
- **The vault object has no delivery URL field** — structurally, not by omission
  (`VaultObject`, spec §3.1). The only route to raw bytes is `intent=original`.

## Verifying it

The contract lints clean and generates working clients on both sides:

```sh
# Lint (0 errors, 0 warnings against redocly.yaml)
npx @redocly/cli lint contract/openapi.yaml

# Generate the TypeScript client types (the caller's side)
npx openapi-typescript contract/openapi.yaml -o client.ts

# Generate the Go server + models (the service's side) — and it compiles
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest \
  -generate types,strict-server,chi-server -package plate \
  contract/openapi.yaml > plate.gen.go
```

Generation is not committed here — it belongs next to each consumer. The
contract is the artifact; the generated code is a build product.

## Scope

This describes the **full v1 surface** — delivery by intent, honest refusal,
asset/rendition reads, the upload broker, job state, and grants. Rollout is
phased (spec §8: read path first, on the demo instance) but the contract is not:
describing an endpoint before it is implemented is deliberate, so the enums are
defined once and clients never break as phases land.
