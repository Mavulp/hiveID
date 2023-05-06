use asserhttp::*;
use serde_json::{json};

use crate::common::TestServer;

#[test]
fn test_auth_endpoints() {
    let server = TestServer::spawn();

    server.get("/api/v2/account").expect_status_unauthorized();
    server.put("/api/v2/account", None).expect_status_unauthorized();
    server.get("/api/v2/invite").expect_status_unauthorized();
    server.post("/api/v2/invite", None).expect_status_unauthorized();
    server.get("/api/v2/invite/admin").expect_status_ok();
    server.post("/api/v2/invite/404", json!({"username":"u","email":"e","password":"p"})).expect_status_ok();
    server.delete("/api/v2/invite/test").expect_status_unauthorized();
    server.post("/api/v2/login", json!({"username":"u","password":"a", "service":"idbin","redirect":"a"})).expect_status_bad_request();
    server.get("/api/v2/service").expect_status_unauthorized();
    server.post("/api/v2/service", None).expect_status_unauthorized();
    server.put("/api/v2/service/idbin", None).expect_status_unauthorized();
    server.post("/api/v2/service/idbin/role", None).expect_status_unauthorized();
    server.delete("/api/v2/service/idbin/role/admin").expect_status_unauthorized();
    server.post("/api/v2/service/idbin/secret", None).expect_status_unauthorized();
}
