# wkdmgr

A self-hosted [OpenPGP Web Key Directory (WKD)](https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service)
server, meant to run behind a reverse proxy that terminates SSO and
forwards the authenticated identity as an HTTP header. It manages
multiple mail domains from a single deployment, minimizes every
published key to exactly the requested address, and never implements
any login system of its own.

## Architecture

Two independent binaries, sharing the `wkdmgr-core` library crate:

- **`wkdmgr-query`** -- public, unauthenticated, read-only. Serves the
  actual WKD HTTP endpoints (`/.well-known/openpgpkey/...`) that mail
  clients hit. It only ever does exact `(domain, hash)` lookups against
  a read-only SQLite handle. It has no filesystem key tree and no state
  of its own beyond that handle, so it's trivial to scale horizontally.

- **`wkdmgr-mgmt`** -- SSO-gated, read/write. Serves a JSON API
  (`/api/*`) used by the bundled Vue frontend. It trusts an HTTP header
  set by the reverse proxy as the authenticated identity, resolves that
  identity to a set of owned email addresses via a pluggable `UserDb`
  backend, and handles all key upload/validation/minimization/storage
  and revocation logic. It is the *only* writer to the SQLite database.

Both bind **exclusively to Unix domain sockets** -- there is no TCP
listener option in v1. Put a reverse proxy (e.g. nginx) in front of
both.

### ⚠️ `wkdmgr-mgmt` must never be exposed directly

`wkdmgr-mgmt` trusts the `Remote-User` header (configurable name)
**unconditionally** as the authenticated identity. It does not
implement a login system and does not try to detect or defend against a
spoofed header -- that is a reverse-proxy responsibility:

- `wkdmgr-mgmt`'s Unix socket must only ever be reachable through a
  reverse proxy that (a) terminates your SSO/auth flow and (b) **strips
  any client-supplied `Remote-User` header before setting its own**. If
  you skip the strip step, any client can impersonate any user.
- Never bind `wkdmgr-mgmt`'s socket somewhere a client could reach
  directly (no public TCP port, no world-writable socket directory).
- `wkdmgr-mgmt` logs a loud warning at startup naming the header it
  trusts, as a reminder of this trust boundary.

`wkdmgr-query` has no such concern: it is public and read-only by
design.

## Building

```sh
cargo build --release
# binaries at target/release/wkdmgr-query and target/release/wkdmgr-mgmt

cd frontend
npm install
npm run build
# type-checks (vue-tsc), then builds the static bundle at frontend/dist/
```

Run the test suite (unit tests across all crates, plus an end-to-end
integration test that spins up both binaries against real Unix sockets
in a temp directory, uploads a key through the mgmt API, and confirms
the query API serves the correctly minimized key at the right hash):

```sh
cargo test --workspace
```

## Keeping the API contract in sync

`wkdmgr-mgmt`'s JSON API is implemented once, in Rust, and the frontend
never hand-writes a second copy of its shape. The Rust handlers and DTOs
in `wkdmgr-mgmt/src/lib.rs` are annotated with [`utoipa`](https://docs.rs/utoipa)
to derive an OpenAPI 3.1 spec directly from the real code (`ApiDoc`),
dumped by `wkdmgr-mgmt --print-openapi`. The frontend's TypeScript
client is generated from that spec via
[`openapi-typescript`](https://openapi-ts.dev/) + [`openapi-fetch`](https://openapi-ts.dev/openapi-fetch/),
so `frontend/src/api.ts` is fully typed against the actual Rust request
and response shapes -- there is no second, hand-maintained schema to let
drift.

`frontend/openapi.json` and `frontend/src/api-types.ts` are build
artifacts, not source: they're gitignored, and `npm run dev`,
`npm run build`, and `npm run typecheck` all regenerate them fresh
first (via `predev`/`prebuild`/`pretypecheck` hooks that run
`npm run generate:api`). This means every frontend build always reflects
the current Rust API contract, so there's nothing to fall out of sync
and nothing to remember to regenerate by hand. The one consequence
worth knowing: building or type-checking the frontend now requires a
working Rust toolchain (`cargo run -p wkdmgr-mgmt` has to succeed) as
well as Node -- there's no path that builds the frontend from source
without also being able to build the backend.

## Configuration

Two YAML files.

### Main config (`config.yaml`, path via `WKDMGR_CONFIG` env var, default `/etc/wkdmgr/config.yaml`)

```yaml
allowed_domains:
  - example-1.tld
  - example-2.tld

db_path: /var/lib/wkdmgr/meta.sqlite3
sso_header_name: Remote-User
userdb_config: /etc/wkdmgr/userdb.yaml

query_socket:
  path: /run/wkdmgr/query.sock
  mode: "0660"

mgmt_socket:
  path: /run/wkdmgr/mgmt.sock
  mode: "0660"

# Optional. If set, wkdmgr-mgmt serves the built frontend bundle
# (frontend/dist) itself as a fallback route. If unset, serve it from
# nginx instead -- see "Serving the frontend" below.
frontend_dist_dir: /usr/share/wkdmgr/frontend/dist
```

Both `wkdmgr-query` and `wkdmgr-mgmt` read this same file. `wkdmgr-query`
only uses `allowed_domains` and `query_socket`; it never opens
`userdb_config` and never writes to `db_path`.

Socket `mode` sets the file's permission bits (default `0660`) after
bind. **Ownership** (which user/group the socket file ends up owned by)
is *not* set in code -- it's simply whatever user/group the process
runs as, which is a systemd `User=`/`Group=` concern. Run each binary as
a dedicated service user, and put your reverse-proxy user (`www-data`,
`nginx`, ...) in that service's group (or vice versa) so it can connect
to the socket without running as the same user.

### Userdb config (`userdb.yaml`, path is `userdb_config` above)

Self-describing: the top-level `backend` field decides the rest of the
shape, so a bad/unknown backend fails fast at startup with a clear
error instead of a confusing partial parse.

#### `backend: flatfile` (default choice for dev/test/MVP)

User records live directly in this file. Zero external dependencies --
this is what lets you run, test, and demo wkdmgr standalone with no
LDAP server.

```yaml
backend: flatfile
users:
  alice:
    addresses:
      - alice@example-1.tld
      - alice.smith@example-2.tld
  bob:
    addresses:
      - bob@example-1.tld
```

`wkdmgr-mgmt` watches this file and hot-reloads it on change -- no
restart needed while iterating.

#### `backend: ldap` (production backend)

Connection details live here; the actual user records stay in the
external directory and are never copied into this file. Read-only:
wkdmgr never writes to LDAP.

```yaml
backend: ldap
uri: ldap://localhost:389
bind_dn: cn=admin,dc=example,dc=org
bind_password_file: /etc/wkdmgr/ldap-bind-password   # mode 0600
base_dn: ou=users,dc=example,dc=org
uid_attr: uid
mail_attr: mail
alias_attr: mailAlternateAddress   # example only -- set to whatever your directory uses
timeout_secs: 10   # optional, default shown
```

`alias_attr` has no universal default across directory schemas, so it's
required. `uid_attr`/`mail_attr` default to `uid`/`mail` if omitted.
The bind password lives in its own file (mode `0600`, owned by the
service user) rather than inline in YAML, like any other secret.

wkdmgr searches `(<uid_attr>=<uid>)` under `base_dn`, and collects the
single-valued `mail_attr` plus every value of the multi-valued
`alias_attr` into one address list, matching attribute names
case-insensitively against what the directory returns (LDAP attribute
descriptors are case-insensitive, and servers don't all echo back the
same casing you searched with).

`timeout_secs` bounds the whole connect+bind+search sequence per
lookup, so an unresponsive directory (packets dropped, a failed-over
host still holding the VIP) fails fast with a `502` instead of hanging
the request.

### Switching backends

Change `backend:` in `userdb.yaml` (and its accompanying fields) and
restart `wkdmgr-mgmt`. No code change, no config change anywhere else --
`Arc<dyn UserDb>` is injected once at startup based on this one field.

## nginx configuration

Both binaries only listen on Unix sockets, so nginx (or your proxy of
choice) is required in front of them. Two independent proxy targets:

### `wkdmgr-query` -- one location block per domain vhost

Each mail domain gets its own server block (Direct method) and, for the
Advanced method, a shared `openpgpkey.<domain>` vhost. Both proxy to the
**same** `wkdmgr-query` socket -- it disambiguates by `Host` header
(Direct) or path (Advanced).

```nginx
# Direct method: example-1.tld/.well-known/openpgpkey/hu/<hash>
server {
    listen 443 ssl;
    server_name example-1.tld;
    # ... your TLS config ...

    location /.well-known/openpgpkey/ {
        proxy_pass http://unix:/run/wkdmgr/query.sock:;
        proxy_set_header Host $host;
    }
}

# Advanced method: openpgpkey.example-1.tld/.well-known/openpgpkey/example-1.tld/hu/<hash>
server {
    listen 443 ssl;
    server_name openpgpkey.example-1.tld;
    # ... your TLS config ...

    location /.well-known/openpgpkey/ {
        proxy_pass http://unix:/run/wkdmgr/query.sock:;
        proxy_set_header Host $host;
    }
}
```

Repeat the pair of server blocks for each domain in `allowed_domains`.

### `wkdmgr-mgmt` -- one vhost, SSO-gated, header stripped and re-set

This is the security-critical block. **Strip any client-supplied
`Remote-User` header before your auth layer sets its own real one**, so
a client can never inject an identity:

```nginx
server {
    listen 443 ssl;
    server_name wkdmgr.example-1.tld;
    # ... your TLS config, plus whatever SSO/auth_request setup
    # authenticates the user and knows their identity ...

    location / {
        # Strip any client-supplied identity header first.
        proxy_set_header Remote-User "";

        # ... your SSO mechanism sets $authenticated_user here,
        # e.g. via auth_request_set from an auth_request subrequest ...
        proxy_set_header Remote-User $authenticated_user;

        proxy_pass http://unix:/run/wkdmgr/mgmt.sock:;
    }
}
```

The exact SSO mechanism (`auth_request`, an OIDC proxy sidecar, etc.) is
outside wkdmgr's scope -- the only hard requirement is that whatever
sets `Remote-User` runs *after* any client-supplied value has been
cleared.

## Serving the frontend

Two options, either is fine:

1. **Serve the built `frontend/dist/` directly from nginx**, as static
   files, on the same vhost/path as `wkdmgr-mgmt`'s `/api/*` (so no CORS
   config is needed). Leave `frontend_dist_dir` unset in `config.yaml`.
2. **Let `wkdmgr-mgmt` serve it** via a fallback route, by setting
   `frontend_dist_dir` in `config.yaml` to the build output directory.
   This repo defaults to this option in its example config, since it's
   one less moving part to configure in nginx.

If you pick option 2, your nginx `location /` block simply proxies
everything (both `/api/*` and the static bundle) to the mgmt socket, as
shown above. If you pick option 1, add a second `location /` block that
serves `frontend_dist_dir` as static files and keep the `/api/`
`location` block proxying to the socket.

## Storage

A single SQLite database (`db_path`) is the entire persistent state --
no separate filesystem key tree. `wkdmgr-mgmt` opens it read/write in
WAL mode (set once at startup); `wkdmgr-query` opens the same file
strictly read-only and never writes to it. Back it up like you would any
real datastore.

### Directory permissions: read-only access after a clean shutdown

**The directory holding `db_path` must be writable by whichever group
`wkdmgr-query` runs as, not just readable.** This is easy to get wrong
under the two-service-user split this README otherwise recommends
(`wkdwriter` for `wkdmgr-mgmt`, `wkdreader` for `wkdmgr-query`, each only
able to read the other's socket) -- but WAL mode specifically needs it:

A WAL-mode database is only fully readable via its `-wal`/`-shm`
sidecar files. When the *last* connection to the database closes
cleanly (a plain `systemctl stop wkdmgr-mgmt`, or a package upgrade's
restart window, with no other connection open at that moment), SQLite
checkpoints and deletes both sidecar files -- but `journal_mode=WAL`
stays recorded in the database file's own header. The next connection,
opening in WAL mode because the header says to, has to recreate `-shm`,
which needs write access to the *directory*, not just the database
file. A reader with read-only directory access gets `attempt to write a
readonly database` on every query, and `wkdmgr-query`'s startup open
still succeeds (it's the per-query `-shm` creation that fails), so this
surfaces only as every WKD lookup 404ing -- indistinguishable from "no
keys published" to anyone watching from outside.

Recommended fix: put both service users in a shared group and make the
directory `2775` (setgid, group-writable) rather than merely
group-readable:

```sh
install -d -o wkdwriter -g wkdshared -m 2775 /var/lib/wkdmgr
usermod -aG wkdshared wkdreader
```

The database file itself can stay whatever `wkdmgr-mgmt` creates it as
(`wkdmgr-query` never needs to write to the file, only to be able to
create `-shm` in its directory). As defense in depth, `wkdmgr-mgmt` also
checkpoints back to `journal_mode=DELETE` on a graceful shutdown
(`SIGTERM`/Ctrl-C) -- which leaves a file any read-only connection can
open with no sidecar files needed at all, and switches back to WAL on
the next start -- but that's best-effort (a `SIGKILL`, or another
process still holding the database open at shutdown time, means it
doesn't happen) and is not a substitute for the directory permission.

## Design decision: minimization strips third-party certifications

Per the WKD spec's own security considerations, a published key contains
*only* the requested address's User ID, its own self-signature, the
primary key, and subkeys with their binding signatures -- no other User
IDs, and no certifications made by other keys. `wkdmgr-core`'s
minimization step enforces this as a hard invariant (see its unit
tests).

This is a deliberate trade-off, not an oversight, and it cuts both ways:

- **Why strip them**: a certification is itself a signature by some
  other key over "I vouch that this UID belongs to this key" --
  publishing all of them over an unauthenticated HTTPS GET would let
  anyone enumerate who has certified a given address, leaking a slice of
  the social graph to any passive observer of WKD traffic.
- **What it costs**: a WKD lookup can only ever establish
  trust-on-first-use (TOFU). It cannot let a verifier confirm a fetched
  key through an existing trust path, since no third-party signatures
  survive the round trip.

If your deployment wants an in-org trust path to survive WKD lookups
without publishing the full social graph, the accepted middle ground is
retaining certifications only from a small, configured set of trusted
issuers (e.g. your organization's own CA key) -- that's not implemented
here and would be a deliberate, separate feature, not a change to what
minimization does by default.

One thing minimization does *not* strip: self-revocation signatures (on
the primary key, the target User ID, or a subkey) are preserved, and
`wkdmgr-query` checks them before serving a key -- see the next section.

## Revocation

A key that is revoked -- its primary key, or its sole retained User ID
after minimization -- is never served: `wkdmgr-query`'s response is the
same bare `404` as "no key published for this address", so revocation
status is never leaked either.

Publishing a revocation works through the existing upload contract, no
separate "revoke" endpoint: `DELETE` the current row, then `POST` the
same cert with the revocation merged in (`gpg --gen-revoke` then
`--import`, or your client's equivalent, followed by re-exporting).
Uploading an already-revoked cert is accepted -- ownership/validity
checks don't reject a revoked User ID, since rejecting it would make it
impossible for an owner to ever publish their own revocation.

Revocation status is computed once at upload time (from the minimized
bytes that are about to be stored) and cached in the `keys.revoked`
column, rather than re-parsed on every WKD lookup: in this system, the
only way revocation status can change at all is a fresh upload, so
there's nothing to recompute in between. The row stays visible (marked
`revoked: true`) in `GET /api/keys` so an owner can still see and manage
it; `wkdmgr-query`'s `SELECT` simply filters `revoked = 0`.

## Key expiry

Unlike revocation, expiry isn't triggered by an upload -- a key that's
live when published can simply age past its own expiration date with no
further action from anyone. So it's checked differently: `keys.expires_at`
stores the primary key's expiration time (`NULL` for a non-expiring
key), and `wkdmgr-query`'s lookup filters `expires_at IS NULL OR
expires_at > <now>` on every request, rather than caching a boolean the
way revocation does. A key stops being served the moment it expires,
with no re-upload needed to trigger that -- and, same as revocation, a
404 for an expired key is indistinguishable from "no key published".

An already-expired cert is rejected at upload time (`400 expired`) --
there's no legitimate reason to publish one, unlike revocation where
publishing an already-revoked cert is exactly the point.

## Address reassignment

Address ownership (per `UserDb`) is only ever checked at upload time; a
row's `uid` doesn't get rechecked afterward. When an address moves
between people -- someone leaves and an alias gets reassigned, a shared
role address changes hands -- `POST /api/keys` from the *new*, currently
verified owner replaces the old row instead of `409`ing forever: without
that, the old owner's key would keep being served indefinitely (mail
encrypted to a key its current holder can't read), the new owner could
never publish (`UNIQUE(domain, wkd_hash)` blocking the insert), and the
new owner couldn't delete their way out either (uid-scoped delete can't
touch a row it doesn't own).

This replacement only happens when the row on file is owned by a
*different* uid than the one now verified for that address, **and**
`UserDb` no longer reports that other uid as an owner of it either --
i.e. it's a genuine reassignment, not two uids that currently both
legitimately own a shared/role address. In the shared case the upload
is refused with `409 already_exists` too (a distinct message from the
same-uid case), rather than letting whichever uid uploads next silently
take the address over. Re-uploading over your own still-current key is
unaffected either way: that still `409`s and still requires an explicit
delete first, per the API contract's "don't silently overwrite"
guarantee.

## Non-goals (v1)

- No built-in TLS -- terminate TLS at nginx.
- No mail-based key-ownership confirmation loop -- `UserDb`-verified
  ownership via the SSO-authenticated uid replaces that.
- No integration with any mail-encryption gateway.
- No S/MIME support -- OpenPGP/WKD only.
- No multi-user administration UI -- each user manages only their own
  addresses.
