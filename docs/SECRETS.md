# Secrets

A deployment of Plate on Fly runs four apps from `deploy/fly.*.plate.toml`: the
api, the worker, the public imgproxy and the granted imgproxy. Each app needs a few
secrets. Keep them in a secrets manager (for example Infisical) as the single source
of truth, and push copies to Fly with `fly secrets import`. Secrets are never
committed: not in a manifest, not in `.env.example`.

| Secret | api | worker | imgproxy | imgproxy-granted |
|---|---|---|---|---|
| `DATABASE_URL` | yes | yes | | |
| `R2_ACCESS_KEY_ID` | yes | yes | as `AWS_ACCESS_KEY_ID` | as `AWS_ACCESS_KEY_ID` |
| `R2_SECRET_ACCESS_KEY` | yes | yes | as `AWS_SECRET_ACCESS_KEY` | as `AWS_SECRET_ACCESS_KEY` |
| `IMGPROXY_KEY` | yes | | yes | yes |
| `IMGPROXY_SALT` | yes | | yes | yes |
| `PLATE_DELIVERY_SIGNING_KEY` | yes | | | |
| `PLATE_JWT_PUBLIC_KEYS` | yes | | | |
| `PLATE_JWT_KEY_ACCOUNTS` | yes | | | |

The imgproxy apps read the AWS-standard names, so they take the same R2 pair under
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. They only read originals, so their
credential needs read access to `vault/*` of the bucket; the api and worker need
write access.

**Config is not a secret.** Hosts, the bucket, the R2 endpoint and region, the
granted-URL TTL and `PLATE_JWT_REQUIRE_KEY_BINDING` are committed in the `[env]` of
`deploy/fly.*.plate.toml`, and `internal/service/deploy_env_config_test.go` checks
them. A Fly secret with the same name as an `[env]` key silently overrides it, so a
config name must never also be a Fly secret.

## Changing a secret

Set the new value in your secrets manager, then push it to every app that uses it
(see the table). Push all of an app's changed names in one `fly secrets import`, so
the app restarts once. Feed the import from the secrets manager's CLI or a file;
never type or paste a value.

Values shared between apps:
- **The R2 pair** goes to all four apps (the imgproxy apps under the `AWS_*` names).
- **`DATABASE_URL`** goes to the api and the worker.
- **`IMGPROXY_KEY` / `IMGPROXY_SALT`** must be the same on the api and both
  imgproxy apps, or every image signature fails. A rotation updates all three apps.

## Verifying

Never by looking at a value. `fly secrets list -a <app>` shows a digest that
depends only on the value, so equal values show equal digests across apps; compare
digests (or a hash you compute without printing the value) to confirm that the
imgproxy key and salt match. After a push, check that `GET <api>/v1/readyz` is 200
with status `ok`, then run your own end-to-end check against a real client.

## Adding a client key

A new client's public key needs two entries, both on the api only: its
`kid=<b64pub>` entry in `PLATE_JWT_PUBLIC_KEYS` and its binding in
`PLATE_JWT_KEY_ACCOUNTS`. Every trusted kid needs a binding, because
`PLATE_JWT_REQUIRE_KEY_BINDING` is `true` and the api refuses to boot with an
unbound key. Update both in your secrets manager and push both names to the api in
one import.

Retiring a kid is the same: remove it from both lists, push to the api.

## Signing tokens

`plate token` signs with the Ed25519 private key, read from `PLATE_JWT_PRIVATE_B64`
(base64 of the private key). That key belongs to the operator or client that issues
tokens, never to a deployed app: keep it in your secrets manager and supply it to
the command's environment only when you mint. Its public half goes into
`PLATE_JWT_PUBLIC_KEYS`.

## Never

- paste a value into a shell (values move from the secrets manager or a file
  straight into the next command);
- keep a `.env` with production values (`.env` is for local development against
  docker compose only);
- print a value to check it, not even part of one (`cut`, `head`, `sed` on a value
  or a key file all print a derivative of it);
- `fly secrets set NAME=<value>` by hand.
