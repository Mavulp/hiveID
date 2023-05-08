use asserhttp::*;
use serde_json::json;

use crate::common::TestServer;

#[test]
fn test_auth_endpoints() {
    let server = TestServer::spawn();

    server.get("/api/v2/accounts").expect_status_unauthorized();
    server
        .put("/api/v2/accounts", None)
        .expect_status_unauthorized();
    server.get("/api/v2/invites").expect_status_unauthorized();
    server
        .post("/api/v2/invites", None)
        .expect_status_unauthorized();
    server.get("/api/v2/invites/admin").expect_status_ok();
    server
        .post(
            "/api/v2/invites/404",
            json!({"username":"u","email":"e","password":"p"}),
        )
        .expect_status_ok();
    server
        .delete("/api/v2/invites/test")
        .expect_status_unauthorized();
    server
        .post(
            "/api/v2/auth/login",
            json!({"username":"u","password":"a", "service":"idbin","redirect":"a"}),
        )
        .expect_status_bad_request();
    server.get("/api/v2/audits").expect_status_unauthorized();
    server.get("/api/v2/services").expect_status_unauthorized();
    server
        .post("/api/v2/services", None)
        .expect_status_unauthorized();
    server
        .put("/api/v2/services/idbin", None)
        .expect_status_unauthorized();
    server
        .post("/api/v2/services/idbin/roles", None)
        .expect_status_unauthorized();
    server
        .delete("/api/v2/services/idbin/roles/admin")
        .expect_status_unauthorized();
    server
        .post("/api/v2/services/idbin/secret", None)
        .expect_status_unauthorized();
}

#[test]
fn test_login() {
    let mut server = TestServer::spawn();

    server.get("/api/v2/accounts").expect_status_unauthorized();
    server.claim_admin_and_auth().unwrap();
    server.get("/api/v2/accounts").expect_status_ok();
}

#[test]
fn test_auth_token_invalidated() {
    let mut server = TestServer::spawn();

    server.get("/api/v2/accounts").expect_status_unauthorized();
    server.claim_admin_and_auth().unwrap();
    server.get("/api/v2/accounts").expect_status_ok();

    // assigning a new role to a user should invalidate all auth tokens for the service, generated
    // before the role was assigned.
    server
        .post(
            &format!("/api/v2/services/idbin/roles"),
            json!({ "name": "newRole" }),
        )
        .expect_status_ok();
    server
        .put(
            "/api/v2/accounts/root/roles/idbin",
            json!({ "rolesToAdd": ["newRole"] }),
        )
        .expect_status_ok();

    server.get("/api/v2/accounts").expect_status_unauthorized();
}

#[test]
fn test_auth_token_invalidated_and_refresh() {
    let mut server = TestServer::spawn();

    server.get("/api/v2/accounts").expect_status_unauthorized();
    server.claim_admin_and_auth().unwrap();
    server.get("/api/v2/accounts").expect_status_ok();

    // assigning a new role to a user should invalidate all auth tokens for the service, generated
    // before the role was assigned.
    server
        .post("/api/v2/services/idbin/roles", json!({ "name": "newRole" }))
        .expect_status_ok();
    server
        .put(
            "/api/v2/accounts/root/roles/idbin",
            json!({ "rolesToAdd": ["newRole"] }),
        )
        .expect_status_ok();

    server.get("/api/v2/accounts").expect_status_unauthorized();

    // HACK: we have to sleep for more than 1s since the JWT stores time in seconds, and we compare
    //       this against when the permissions were last updated, which is also in seconds.
    std::thread::sleep_ms(1500);

    server.refresh_auth().unwrap();

    server.get("/api/v2/accounts").expect_status_ok();
}
