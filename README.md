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
# static bundle at frontend/dist/
```

Run the test suite (unit tests across all crates, plus an end-to-end
integration test that spins up both binaries against real Unix sockets
in a temp directory, uploads a key through the mgmt API, and confirms
the query API serves the correctly minimized key at the right hash):

```sh
cargo test --workspace
```

## Configuration

Two YAML files.

### Main config (`config.yaml`, path via `WKDMGR_CONFIG` env var, default `/etc/wkdmgr/config.yaml`)

```yaml
allowed_domains:
  - example-1.tld
  - example-2.tld

db_path: /var/lib/wkdmgr/meta.sqlite3
hooks_dir: /etc/wkdmgr/hooks.d
sso_header_name: Remote-User
userdb_config: /etc/wkdmgr/userdb.yaml

query_socket:
  path: /run/wkdmgr/query.sock
  mode: "0660"

mgmt_socket:
  path: /run/wkdmgr/mgmt.sock
  mode: "0660"

# Optional. Best-effort hook timeout in seconds (default 10).
hook_timeout_secs: 10

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
```

`alias_attr` has no universal default across directory schemas, so it's
required. `uid_attr`/`mail_attr` default to `uid`/`mail` if omitted.
The bind password lives in its own file (mode `0600`, owned by the
service user) rather than inline in YAML, like any other secret.

wkdmgr searches `(<uid_attr>=<uid>)` under `base_dn`, and collects the
single-valued `mail_attr` plus every value of the multi-valued
`alias_attr` into one address list.

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

## Hooks

`hooks.d/on_key_add/` and `hooks.d/on_key_remove/` are the deferred
integration point (e.g. for feeding a mail-encryption gateway's
keyring). They ship empty in this repo aside from a `README` in each
explaining the exact calling convention. See those files for details;
in short: every executable script in the relevant directory runs, in
filename sort order, as `script <email> <domain>` (with the minimized
key piped to stdin for `on_key_add`), with a timeout, best-effort, after
the underlying database operation has already succeeded.

## Storage

A single SQLite database (`db_path`) is the entire persistent state --
no separate filesystem key tree. `wkdmgr-mgmt` opens it read/write in
WAL mode (set once at startup); `wkdmgr-query` opens the same file
strictly read-only and never writes to it. Back it up like you would any
real datastore.

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

## Non-goals (v1)

- No built-in TLS -- terminate TLS at nginx.
- No mail-based key-ownership confirmation loop -- `UserDb`-verified
  ownership via the SSO-authenticated uid replaces that.
- No integration with any mail-encryption gateway -- that's what the
  hooks mechanism exists to defer.
- No S/MIME support -- OpenPGP/WKD only.
- No multi-user administration UI -- each user manages only their own
  addresses.
