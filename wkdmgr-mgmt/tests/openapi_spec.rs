//! Guards against the two API implementations (this Rust service and the
//! Vue frontend's generated TypeScript client) drifting apart: fails if
//! the OpenAPI spec derived from the live `wkdmgr_mgmt::ApiDoc`
//! (`utoipa` annotations on the actual handlers/DTOs) no longer matches
//! the copy checked into `frontend/openapi.json`, which is what
//! `frontend/src/api-types.ts` was generated from.

use utoipa::OpenApi;
use wkdmgr_mgmt::ApiDoc;

#[test]
fn openapi_spec_is_up_to_date() {
    let generated = ApiDoc::openapi().to_pretty_json().unwrap();
    let generated_value: serde_json::Value = serde_json::from_str(&generated).unwrap();

    let checked_in_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../frontend/openapi.json");
    let checked_in_raw = std::fs::read_to_string(checked_in_path).unwrap_or_else(|e| {
        panic!(
            "failed to read {checked_in_path}: {e}\n\nGenerate it with `npm run generate:api` \
             in frontend/."
        )
    });
    let checked_in_value: serde_json::Value = serde_json::from_str(&checked_in_raw)
        .unwrap_or_else(|e| panic!("{checked_in_path} is not valid JSON: {e}"));

    assert_eq!(
        generated_value, checked_in_value,
        "\n\nfrontend/openapi.json is stale: the Rust API contract (wkdmgr_mgmt::ApiDoc, i.e. \
         the utoipa-annotated handlers and DTOs in wkdmgr-mgmt/src/lib.rs) has changed since it \
         was last generated.\n\nRun `npm run generate:api` in frontend/ and commit the result \
         (openapi.json and src/api-types.ts) alongside this change.\n"
    );
}
