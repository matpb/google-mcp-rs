//! Proves `stdio` mode never reads `./.env`: a foreign `.env` in the launch
//! directory must not leak into config or overwrite the real keyfile.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "google-mcp-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn stdio_ignores_cwd_dotenv_and_keeps_its_own_keyfile() {
    let cwd_dir = TempDir::new("cwd");
    let db_dir = TempDir::new("db");

    // 32 zero bytes, base64url-encoded — a validly-shaped but wrong key.
    let foreign_storage_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    std::fs::write(
        cwd_dir.path().join(".env"),
        format!("GOOGLE_CLIENT_ID=from-cwd\nSTORAGE_ENCRYPTION_KEY={foreign_storage_key}\n"),
    )
    .expect("write cwd .env");

    let db_path = db_dir.path().join("google-mcp.db");

    let mut child = Command::new(env!("CARGO_BIN_EXE_google-mcp"))
        .arg("stdio")
        .current_dir(cwd_dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("DATABASE_URL", &db_path)
        .env("GOOGLE_CLIENT_ID", "from-env")
        .env("GOOGLE_CLIENT_SECRET", "x")
        .env("BASE_URL", "http://localhost:18999")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn google-mcp stdio");

    let mut stdin = child.stdin.take().expect("child stdin");
    let init = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#,
        r#"{"protocolVersion":"2025-06-18","capabilities":{},"#,
        r#""clientInfo":{"name":"test","version":"0"}}}"#
    );
    writeln!(stdin, "{init}").expect("write initialize line");
    stdin.flush().ok();

    // Let it start and process the line before closing stdin.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "server exited early instead of starting normally"
    );

    drop(stdin); // EOF on the MCP transport

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("server did not exit within 10s of stdin EOF");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "server exited with error: {status:?}");

    let keyfile_path = PathBuf::from(format!("{}.keys", db_path.display()));
    let keyfile = std::fs::read_to_string(&keyfile_path).expect("read keyfile");
    assert!(
        !keyfile.contains(foreign_storage_key),
        "cwd .env's STORAGE_ENCRYPTION_KEY leaked into the keyfile"
    );
}
