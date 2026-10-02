# Secrets

Every Plate secret lives in **Infisical**: project `plate`
(`8d235b61-b9c9-4754-9bdc-73cc7db55c05`), env `prod`. Infisical is the source of
truth; Fly holds copies, pushed with the registry repo's
`scripts/secrets/infisical-to-fly.sh`. Nothing else holds them.

| Infisical name (`plate`/`prod`) | api | worker | imgproxy | imgproxy-granted |
|---|---|---|---|---|
| `DATABASE_URL` | yes | yes | | |
| `R2_ACCESS_KEY_ID` | yes | yes | as `AWS_ACCESS_KEY_ID` | as `AWS_ACCESS_KEY_ID` |
| `R2_SECRET_ACCESS_KEY` | yes | yes | as `AWS_SECRET_ACCESS_KEY` | as `AWS_SECRET_ACCESS_KEY` |
| `IMGPROXY_KEY` | yes | | yes | yes |
| `IMGPROXY_SALT` | yes | | yes | yes |
| `PLATE_DELIVERY_SIGNING_KEY` | yes | | | |
| `PLATE_JWT_PUBLIC_KEYS` | yes | | | |
| `PLATE_JWT_KEY_ACCOUNTS` | yes | | | |

The apps are `esf-plate-api`, `esf-plate-worker`, `esf-plate-imgproxy` and
`esf-plate-imgproxy-granted`.

**Config is not a secret.** Hosts, the bucket, the R2 endpoint and region, the
granted-URL TTL and `PLATE_JWT_REQUIRE_KEY_BINDING` are committed in the `[env]` of
`deploy/fly.*.plate.toml`, and `internal/service/deploy_env_config_test.go` checks
them. A Fly secret with the same name as an `[env]` key silently overrides it, so a
config name must never also be a Fly secret.

## Changing a secret

Set the new value in Infisical `prod` (the web UI, or the CLI from a file), then
push it, one app per paste, from `~/Dev/registry`:

```
sh scripts/secrets/infisical-to-fly.sh 8d235b61-b9c9-4754-9bdc-73cc7db55c05 prod <app> NAME[:FLYNAME] [...]
```

All names in one call go in one `fly secrets import`, so the app restarts once. It
prints `NAME -> FLYNAME: ready (N bytes)` and never a value. `NAME:FLYNAME` pushes
under a different Fly name; the imgproxy apps take the R2 pair as
`R2_ACCESS_KEY_ID:AWS_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY:AWS_SECRET_ACCESS_KEY`.

Values shared between apps:
- **The R2 pair** goes to all four apps (imgproxy and imgproxy-granted with the
  `AWS_*` mapping).
- **`DATABASE_URL`** goes to the worker first, then the api.
- **`IMGPROXY_KEY` / `IMGPROXY_SALT`** must be the same on the api and both
  imgproxy apps, or every image signature fails. The current values were copied into
  Infisical, deliberately not rotated yet; a rotation pushes all three apps.

## Verifying

Never by looking at a value. `fly secrets list -a <app>` shows a digest that
depends only on the value, so equal values show equal digests across apps. That is
the only way to check the imgproxy apps. After a push:
1. `GET https://plate-api.everysinglefile.com/v1/readyz` is 200 with status `ok`;
2. the registry slice passes (`go run ./acceptance/slice verify` in `~/Dev/registry`);
3. the uriaran check passes (`~/Dev/registry/.scratch/uri-check.sh`).

## Adding a client key

A new client's public key goes into Infisical: its `kid=<b64pub>` entry in
`PLATE_JWT_PUBLIC_KEYS` and its binding in `PLATE_JWT_KEY_ACCOUNTS` (every trusted
kid needs one, because `PLATE_JWT_REQUIRE_KEY_BINDING` is `true` and the api refuses
to boot with an unbound key). Then push both names to the api only:

```
sh scripts/secrets/infisical-to-fly.sh 8d235b61-b9c9-4754-9bdc-73cc7db55c05 prod esf-plate-api PLATE_JWT_PUBLIC_KEYS PLATE_JWT_KEY_ACCOUNTS
```

Retiring a kid is the same: remove it from both lists, push to the api.

## Never

- paste a value into a shell (values move file → CLI, or `$(infisical … --plain)`
  straight into another command);
- keep a `.env` with production values;
- print a value to check it, not even part of one (`cut`, `head`, `sed` on a value
  or a key file all print a derivative of it);
- `fly secrets set NAME=<value>` by hand.
