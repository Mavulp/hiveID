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
