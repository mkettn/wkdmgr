//! End-to-end integration test: spins up both `wkdmgr-mgmt` and
//! `wkdmgr-query` routers against real Unix domain sockets in a temp
//! directory, simulates an authenticated upload via the mgmt socket
//! (manually setting the SSO header, the way nginx would), and confirms
//! the query socket then serves the correctly minimized key at the
//! correct WKD hash path -- for both the Direct and Advanced variants.

use sequoia_openpgp::armor;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize as _;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wkdmgr_core::userdb::FlatFileUserDb;
use wkdmgr_mgmt::{build_app as build_mgmt_app, AppState as MgmtAppState};
use wkdmgr_query::{build_app as build_query_app, AppState as QueryAppState};

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn http_request(
    socket_path: &Path,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .expect("connect to unix socket");

    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    request.push_str(&format!("Host: {host}\r\n"));
    request.push_str("Connection: close\r\n");
    for (k, v) in extra_headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await.unwrap();
    if !body.is_empty() {
        stream.write_all(body).await.unwrap();
    }
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();

    let split_at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has header/body separator");
    let header_str = String::from_utf8_lossy(&raw[..split_at]).into_owned();
    let body = raw[split_at + 4..].to_vec();

    let mut lines = header_str.lines();
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("status code is numeric");

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    HttpResponse {
        status,
        headers,
        body,
    }
}

fn generate_armored_cert(uids: &[&str]) -> (String, sequoia_openpgp::Cert) {
    let mut builder = CertBuilder::new().add_signing_subkey();
    for uid in uids {
        builder = builder.add_userid(*uid);
    }
    let (cert, _revocation) = builder.generate().unwrap();

    let mut buf = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        cert.serialize(&mut writer).unwrap();
        writer.finalize().unwrap();
    }
    (String::from_utf8(buf).unwrap(), cert)
}

struct TestHarness {
    dir: tempfile::TempDir,
    mgmt_socket: PathBuf,
    query_socket: PathBuf,
    _mgmt_task: tokio::task::JoinHandle<()>,
    _query_task: tokio::task::JoinHandle<()>,
}

async fn spawn_harness() -> TestHarness {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("meta.sqlite3");
    let userdb_path = dir.path().join("userdb.yaml");
    let mgmt_socket = dir.path().join("mgmt.sock");
    let query_socket = dir.path().join("query.sock");
    let hooks_dir = dir.path().join("hooks.d");

    tokio::fs::write(
        &userdb_path,
        r#"
backend: flatfile
users:
  alice:
    addresses:
      - alice@example.com
"#,
    )
    .await
    .unwrap();

    let allowed_domains: Vec<String> = vec!["example.com".to_string()];

    // --- mgmt ---
    let userdb = Arc::new(FlatFileUserDb::load(userdb_path).unwrap());
    let conn = wkdmgr_core::storage::open_writable(&db_path).unwrap();
    let mgmt_state = MgmtAppState {
        db: Arc::new(Mutex::new(conn)),
        allowed_domains: Arc::new(allowed_domains.clone()),
        sso_header_name: Arc::new("Remote-User".to_string()),
        userdb,
        hooks_dir: Arc::new(hooks_dir),
        hook_timeout: Duration::from_secs(5),
    };
    let mgmt_app = build_mgmt_app(mgmt_state, None);
    let mgmt_listener = tokio::net::UnixListener::bind(&mgmt_socket).unwrap();
    let mgmt_task = tokio::spawn(async move {
        axum::serve(mgmt_listener, mgmt_app).await.unwrap();
    });

    // --- query ---
    let query_state = QueryAppState::new(db_path.clone(), allowed_domains);
    let query_app = build_query_app(query_state);
    let query_listener = tokio::net::UnixListener::bind(&query_socket).unwrap();
    let query_task = tokio::spawn(async move {
        axum::serve(query_listener, query_app).await.unwrap();
    });

    // Give the listeners a moment to come up (spawned tasks run on the
    // same runtime, but the connect below will simply retry-friendly
    // fail fast if we race it, so a short yield is enough in practice).
    tokio::task::yield_now().await;

    TestHarness {
        dir,
        mgmt_socket,
        query_socket,
        _mgmt_task: mgmt_task,
        _query_task: query_task,
    }
}

#[tokio::test]
async fn end_to_end_upload_then_query_direct_and_advanced() {
    let harness = spawn_harness().await;
    let _ = &harness.dir;

    let (armored, _cert) = generate_armored_cert(&[
        "Alice <alice@example.com>",
        "Other Name <other@example.com>",
    ]);

    let upload_body = serde_json::json!({
        "address": "alice@example.com",
        "key": armored,
    })
    .to_string();

    let resp = http_request(
        &harness.mgmt_socket,
        "POST",
        "/api/keys",
        "mgmt.local",
        &[
            ("Remote-User", "alice"),
            ("Content-Type", "application/json"),
        ],
        upload_body.as_bytes(),
    )
    .await;
    assert_eq!(
        resp.status,
        201,
        "upload failed: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let upload_json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let key_id = upload_json["id"].as_str().unwrap().to_string();
    assert_eq!(upload_json["address"], "alice@example.com");
    assert_eq!(upload_json["domain"], "example.com");

    // GET /api/me reflects the address list from the flatfile UserDb.
    let me_resp = http_request(
        &harness.mgmt_socket,
        "GET",
        "/api/me",
        "mgmt.local",
        &[("Remote-User", "alice")],
        b"",
    )
    .await;
    assert_eq!(me_resp.status, 200);
    let me_json: serde_json::Value = serde_json::from_slice(&me_resp.body).unwrap();
    assert_eq!(me_json["uid"], "alice");
    assert_eq!(me_json["addresses"][0], "alice@example.com");

    // GET /api/keys lists the uploaded key.
    let list_resp = http_request(
        &harness.mgmt_socket,
        "GET",
        "/api/keys",
        "mgmt.local",
        &[("Remote-User", "alice")],
        b"",
    )
    .await;
    assert_eq!(list_resp.status, 200);
    let list_json: serde_json::Value = serde_json::from_slice(&list_resp.body).unwrap();
    assert_eq!(list_json.as_array().unwrap().len(), 1);

    // Missing SSO header must be rejected with 401.
    let unauth_resp = http_request(
        &harness.mgmt_socket,
        "GET",
        "/api/me",
        "mgmt.local",
        &[],
        b"",
    )
    .await;
    assert_eq!(unauth_resp.status, 401);

    // Duplicate upload for the same address must 409.
    let dup_resp = http_request(
        &harness.mgmt_socket,
        "POST",
        "/api/keys",
        "mgmt.local",
        &[
            ("Remote-User", "alice"),
            ("Content-Type", "application/json"),
        ],
        upload_body.as_bytes(),
    )
    .await;
    assert_eq!(dup_resp.status, 409);
    let dup_json: serde_json::Value = serde_json::from_slice(&dup_resp.body).unwrap();
    assert_eq!(dup_json["error"], "already_exists");

    // Uploading against an address the uid doesn't own is rejected.
    let (other_armored, _) = generate_armored_cert(&["Mallory <mallory@example.com>"]);
    let bad_owner_body = serde_json::json!({
        "address": "mallory@example.com",
        "key": other_armored,
    })
    .to_string();
    let bad_owner_resp = http_request(
        &harness.mgmt_socket,
        "POST",
        "/api/keys",
        "mgmt.local",
        &[
            ("Remote-User", "alice"),
            ("Content-Type", "application/json"),
        ],
        bad_owner_body.as_bytes(),
    )
    .await;
    assert_eq!(bad_owner_resp.status, 400);
    let bad_owner_json: serde_json::Value = serde_json::from_slice(&bad_owner_resp.body).unwrap();
    assert_eq!(bad_owner_json["error"], "address_not_owned");

    // --- Now confirm the query socket serves the minimized key. ---
    let (wkd_hash, domain) =
        wkdmgr_core::wkd_hash::wkd_hash_for_address("alice@example.com").unwrap();
    assert_eq!(domain, "example.com");

    // Direct variant: domain comes from the Host header.
    let direct_path = format!("/.well-known/openpgpkey/hu/{wkd_hash}");
    let direct_resp = http_request(
        &harness.query_socket,
        "GET",
        &direct_path,
        "example.com",
        &[],
        b"",
    )
    .await;
    assert_eq!(direct_resp.status, 200);
    assert_eq!(
        direct_resp.headers.get("content-type").map(String::as_str),
        Some("application/octet-stream")
    );

    let minimized = wkdmgr_core::openpgp::parse_cert(&direct_resp.body).unwrap();
    let uids: Vec<_> = minimized.userids().collect();
    assert_eq!(uids.len(), 1, "minimized cert must contain exactly one UID");
    assert_eq!(
        uids[0].userid().email().unwrap().unwrap(),
        "alice@example.com"
    );

    // Advanced variant: domain comes from the path.
    let advanced_path = format!("/.well-known/openpgpkey/example.com/hu/{wkd_hash}");
    let advanced_resp = http_request(
        &harness.query_socket,
        "GET",
        &advanced_path,
        "irrelevant.invalid",
        &[],
        b"",
    )
    .await;
    assert_eq!(advanced_resp.status, 200);
    assert_eq!(advanced_resp.body, direct_resp.body);

    // Policy endpoints: empty body, text/plain.
    let policy_resp = http_request(
        &harness.query_socket,
        "GET",
        "/.well-known/openpgpkey/policy",
        "example.com",
        &[],
        b"",
    )
    .await;
    assert_eq!(policy_resp.status, 200);
    assert_eq!(
        policy_resp.headers.get("content-type").map(String::as_str),
        Some("text/plain")
    );
    assert!(policy_resp.body.is_empty());

    let adv_policy_resp = http_request(
        &harness.query_socket,
        "GET",
        "/.well-known/openpgpkey/example.com/policy",
        "irrelevant.invalid",
        &[],
        b"",
    )
    .await;
    assert_eq!(adv_policy_resp.status, 200);

    // Unknown hash -> 404, same shape as a domain that isn't allowed.
    let missing_resp = http_request(
        &harness.query_socket,
        "GET",
        "/.well-known/openpgpkey/hu/doesnotexist00000000000000000000",
        "example.com",
        &[],
        b"",
    )
    .await;
    assert_eq!(missing_resp.status, 404);

    let unknown_domain_resp = http_request(
        &harness.query_socket,
        "GET",
        &format!("/.well-known/openpgpkey/hu/{wkd_hash}"),
        "not-served.example",
        &[],
        b"",
    )
    .await;
    assert_eq!(unknown_domain_resp.status, 404);

    // --- Revoke the key via DELETE and confirm it disappears from query. ---
    let delete_resp = http_request(
        &harness.mgmt_socket,
        "DELETE",
        &format!("/api/keys/{key_id}"),
        "mgmt.local",
        &[("Remote-User", "alice")],
        b"",
    )
    .await;
    assert_eq!(delete_resp.status, 204);

    // Deleting again (or deleting someone else's key) 404s, not 500,
    // and never distinguishes "not yours" from "doesn't exist".
    let delete_again_resp = http_request(
        &harness.mgmt_socket,
        "DELETE",
        &format!("/api/keys/{key_id}"),
        "mgmt.local",
        &[("Remote-User", "alice")],
        b"",
    )
    .await;
    assert_eq!(delete_again_resp.status, 404);

    let after_delete_resp = http_request(
        &harness.query_socket,
        "GET",
        &direct_path,
        "example.com",
        &[],
        b"",
    )
    .await;
    assert_eq!(after_delete_resp.status, 404);
}

/// Generate an armored cert for `uid_str` whose sole User ID has
/// already been revoked (a self-revocation merged into the same cert,
/// the way a real client would produce and publish one).
fn generate_armored_cert_with_uid_revoked(uid_str: &str) -> String {
    use sequoia_openpgp::packet::signature::SignatureBuilder;
    use sequoia_openpgp::packet::{Packet, UserID};
    use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};

    let uid: UserID = uid_str.into();
    let (cert, _revocation) = CertBuilder::new()
        .add_signing_subkey()
        .add_userid(uid_str)
        .generate()
        .unwrap();

    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let target = cert.userids().find(|u| u.userid() == &uid).unwrap();
    let uid_revocation = target
        .userid()
        .bind(
            &mut signer,
            &cert,
            SignatureBuilder::new(SignatureType::CertificationRevocation)
                .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"testing")
                .unwrap(),
        )
        .unwrap();
    let revoked_cert = cert
        .insert_packets(vec![Packet::from(uid_revocation)])
        .unwrap()
        .0;

    let mut buf = Vec::new();
    {
        let mut writer = armor::Writer::new(&mut buf, armor::Kind::PublicKey).unwrap();
        revoked_cert.serialize(&mut writer).unwrap();
        writer.finalize().unwrap();
    }
    String::from_utf8(buf).unwrap()
}

/// End-to-end proof for the revocation fix: publishing an
/// already-revoked cert must succeed (an owner has to be able to push
/// their own revocation through this API), but the query socket must
/// never actually serve it -- same 404 as if no key existed at all.
#[tokio::test]
async fn revoked_key_upload_succeeds_but_query_never_serves_it() {
    let harness = spawn_harness().await;
    let armored = generate_armored_cert_with_uid_revoked("Alice <alice@example.com>");

    let upload_body = serde_json::json!({
        "address": "alice@example.com",
        "key": armored,
    })
    .to_string();

    let resp = http_request(
        &harness.mgmt_socket,
        "POST",
        "/api/keys",
        "mgmt.local",
        &[
            ("Remote-User", "alice"),
            ("Content-Type", "application/json"),
        ],
        upload_body.as_bytes(),
    )
    .await;
    assert_eq!(
        resp.status,
        201,
        "publishing an owner's own revocation must succeed: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let upload_json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(upload_json["revoked"], true);

    // The row is still visible to its owner in /api/keys, marked revoked...
    let list_resp = http_request(
        &harness.mgmt_socket,
        "GET",
        "/api/keys",
        "mgmt.local",
        &[("Remote-User", "alice")],
        b"",
    )
    .await;
    let list_json: serde_json::Value = serde_json::from_slice(&list_resp.body).unwrap();
    assert_eq!(list_json[0]["revoked"], true);

    // ...but wkdmgr-query never serves it: same 404 as "no key published".
    let (wkd_hash, domain) =
        wkdmgr_core::wkd_hash::wkd_hash_for_address("alice@example.com").unwrap();
    assert_eq!(domain, "example.com");
    let direct_path = format!("/.well-known/openpgpkey/hu/{wkd_hash}");
    let query_resp = http_request(
        &harness.query_socket,
        "GET",
        &direct_path,
        "example.com",
        &[],
        b"",
    )
    .await;
    assert_eq!(
        query_resp.status, 404,
        "a revoked key must never be served over WKD"
    );
}
