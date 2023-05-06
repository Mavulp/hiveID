use assert_cmd::prelude::*;

use std::process::{Child, Command, Stdio};
use temp_dir::TempDir;
use ureq::OrAnyStatus;

pub struct TestServer {
    addr: String,
    auth_token: Option<String>,
    _temp_dir: TempDir,
    server: Child,
}

impl TestServer {
    pub fn spawn() -> Self {
        spawn_idbin()
    }

    pub fn claim_admin_and_auth(&mut self) -> anyhow::Result<()> {
        ureq::post(&format!("{}/api/v2/invites/admin", self.addr)).send_json(ureq::json!({
            "email": "email@email.com",
            "username": "root",
            "password": "pass"
        }))?;

        let response = ureq::builder()
            .redirects(0)
            .build()
            .post(&format!("{}/api/v2/login", self.addr))
            .send_json(ureq::json!({
                "username": "root",
                "password": "pass",
                "service": "idbin",
                "redirect": "/",
            }))?;

        if response.status() != 302 {
            anyhow::bail!("Invalid login");
        }

        let location = response
            .header("Location")
            .ok_or_else(|| anyhow::anyhow!("No location header"))?;

        let (_, rest) = location.split_once("token=").unwrap();

        self.auth_token = Some(rest.to_string());

        Ok(())
    }

    pub fn delete(&self, path: &str) -> Result<ureq::Response, ureq::Transport> {
        let mut req = ureq::delete(&format!("{}{}", self.addr, path));

        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        req.call().or_any_status()
    }

    pub fn get(&self, path: &str) -> Result<ureq::Response, ureq::Transport> {
        let mut req = ureq::get(&format!("{}{}", self.addr, path));

        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        req.call().or_any_status()
    }

    pub fn put<J: Into<Option<serde_json::Value>>>(
        &self,
        path: &str,
        json: J,
    ) -> Result<ureq::Response, ureq::Transport> {
        let mut req = ureq::put(&format!("{}{}", self.addr, path));

        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        if let Some(json) = json.into() {
            req.send_json(json).or_any_status()
        } else {
            req.call().or_any_status()
        }
    }

    pub fn post<J: Into<Option<serde_json::Value>>>(
        &self,
        path: &str,
        json: J,
    ) -> Result<ureq::Response, ureq::Transport> {
        let mut req = ureq::post(&format!("{}{}", self.addr, path));

        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }

        if let Some(json) = json.into() {
            req.send_json(json).or_any_status()
        } else {
            req.call().or_any_status()
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.server.kill().unwrap();
        self.server.wait().unwrap();
    }
}

fn spawn_idbin() -> TestServer {
    let d = TempDir::new().unwrap();

    let port = portpicker::pick_unused_port().expect("No ports free");
    let addr = format!("127.0.0.1:{port}");

    let mut cmd = Command::cargo_bin("idbin").unwrap();
    cmd.env("RUST_LOG", "debug");
    cmd.env("DB_PATH", d.child("db.sqlite"));
    cmd.env("BIND_ADDRESS", &addr);
    cmd.env("IDP_SECRET_KEY", "aHVudGVyMg==");
    cmd.env("IDP_REFRESH_ADDR", format!("http://{addr}/refresh"));
    cmd.stdout(Stdio::piped());

    let mut output = cmd.spawn().unwrap();
    let stdout = output.stdout.take().unwrap();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            reader.read_line(&mut line).unwrap();
            print!("{line}");
            line.clear();
        }
    });

    let addr = format!("http://127.0.0.1:{port}");

    loop {
        if let Err(e) = ureq::get(&addr).call() {
            if let ureq::Error::Transport(t) = e {
                if t.kind() == ureq::ErrorKind::ConnectionFailed {
                    continue;
                }
            }
        }

        break;
    }

    TestServer {
        addr,
        auth_token: None,
        _temp_dir: d,
        server: output,
    }
}
