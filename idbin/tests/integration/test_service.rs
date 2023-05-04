use asserhttp::*;
use jsonpath_rust::{JsonPathFinder, JsonPathInst, JsonPathQuery, JsonPathValue};
use serde_json::{json, Value};

use crate::common::TestServer;

#[test]
fn test_service() {
    let mut server = TestServer::spawn();

    server.claim_admin_and_auth().unwrap();

    server
        .get(&format!("/api/v2/service"))
        .unwrap()
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| assert_eq!(v.path("$.[*].id").unwrap(), json!(["idbin"])));

    server
        .post(
            "/api/v2/service",
            json!({
                "id": "myNewService"
            }),
        )
        .unwrap()
        .expect_status_ok();

    server
        .get(&format!("/api/v2/service"))
        .unwrap()
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(
                v.path("$.[*].id").unwrap(),
                json!(["idbin", "myNewService"])
            )
        });
}
