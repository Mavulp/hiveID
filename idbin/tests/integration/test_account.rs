use asserhttp::*;
use serde_json::json;

use crate::common::TestServer;

#[test]
fn test_account() {
    let mut server = TestServer::spawn();

    server.claim_admin_and_auth().unwrap();

    server
        .get(&format!("/api/v2/accounts"))
        .unwrap()
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json_eq(json!({
            "email": "email@email.com",
            "username": "root",
        }));

    server
        .put(
            "/api/v2/accounts",
            json!({
                "newEmail": "new@email.com"
            }),
        )
        .unwrap()
        .expect_status_ok();

    server
        .get(&format!("/api/v2/accounts"))
        .unwrap()
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json_eq(json!({
            "email": "new@email.com",
            "username": "root",
        }));
}
