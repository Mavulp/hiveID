use asserhttp::*;
use common::TestServer;
use serde_json::json;

mod common;

#[test]
fn test_account() {
    let mut server = TestServer::spawn();

    server.claim_admin_and_auth().unwrap();

    server
        .get(&format!("/api/v2/account"))
        .unwrap()
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json_eq(json!({
            "email": "email@email.com",
            "username": "root",
        }));
}
