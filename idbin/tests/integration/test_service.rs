use asserhttp::*;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};

use crate::common::TestServer;

#[test]
fn test_create_service() {
    let mut server = TestServer::spawn();
    server.claim_admin_and_auth().unwrap();

    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| assert_eq!(v.path("$.[*].id").unwrap(), json!(["idbin"])));

    create_service(&mut server, "myNewService").expect_status_ok();

    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(
                v.path("$.[*].id").unwrap(),
                json!(["idbin", "myNewService"])
            )
        });
}

#[test]
fn test_create_service_empty_name() {
    let mut server = TestServer::spawn();
    server.claim_admin_and_auth().unwrap();

    create_service(&mut server, "").expect_status_bad_request();
}

#[test]
fn test_create_duplicate_service() {
    let mut server = TestServer::spawn();
    server.claim_admin_and_auth().unwrap();

    create_service(&mut server, "a").expect_status_ok();

    create_service(&mut server, "a").expect_status_server_error();
}

#[test]
fn test_create_role() {
    let mut server = TestServer::spawn();
    server.claim_admin_and_auth().unwrap();

    create_service(&mut server, "a").expect_status_ok();
    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(v.path("$.[?(@.id == 'a')].roles").unwrap(), json!([[]]))
        });

    create_role(&mut server, "a", "newRole").expect_status_ok();

    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(
                v.path("$.[?(@.id == 'a')].roles").unwrap(),
                json!([["newRole"]])
            )
        });
}

#[test]
fn test_delete_role() {
    let mut server = TestServer::spawn();
    server.claim_admin_and_auth().unwrap();

    create_service(&mut server, "a").expect_status_ok();
    create_role(&mut server, "a", "newRole").expect_status_ok();

    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(
                v.path("$.[?(@.id == 'a')].roles").unwrap(),
                json!([["newRole"]])
            )
        });

    delete_role(&mut server, "a", "newRole").expect_status_ok();

    get_services(&mut server)
        .expect_status_ok()
        .expect_content_type_json()
        .expect_body_json(|v: Value| {
            assert_eq!(v.path("$.[?(@.id == 'a')].roles").unwrap(), json!([[]]))
        });
}

fn get_services(server: &mut TestServer) -> Result<ureq::Response, ureq::Transport> {
    server.get("/api/v2/services")
}

fn create_service(server: &mut TestServer, id: &str) -> Result<ureq::Response, ureq::Transport> {
    server.post("/api/v2/services", json!({ "id": id }))
}

fn create_role(
    server: &mut TestServer,
    service_id: &str,
    role: &str,
) -> Result<ureq::Response, ureq::Transport> {
    server.post(
        &format!("/api/v2/services/{service_id}/roles"),
        json!({ "name": role }),
    )
}

fn delete_role(
    server: &mut TestServer,
    service_id: &str,
    role: &str,
) -> Result<ureq::Response, ureq::Transport> {
    server.delete(&format!("/api/v2/services/{service_id}/roles/{role}"))
}
