#![cfg(unix)]
#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn key_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn temporary_path(label: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "out-local-process-{label}-{}-{sequence}",
        std::process::id()
    ))
}

fn start_node(mode: &str, backend: &str, database: &Path, socket: &Path, key: &str) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_out-node-local"))
        .args([
            mode,
            backend,
            "devnet",
            database.to_str().expect("database path"),
            socket.to_str().expect("socket path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start local node");
    let mut stdin = child.stdin.take().expect("node stdin");
    writeln!(stdin, "{key}").expect("node key");
    drop(stdin);
    child
}

fn wait_for_socket(child: &mut Child, socket: &Path) {
    for _ in 0..10_000 {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("node status") {
            panic!("node exited before binding socket: {status}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = child.kill();
    panic!("node socket was not created within bound");
}

fn run_operator(socket: &Path, sequence: u64, arguments: &[&str], key: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_out-operator"))
        .arg(socket.to_str().expect("socket path"))
        .arg(sequence.to_string())
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start operator");
    let mut stdin = child.stdin.take().expect("operator stdin");
    writeln!(stdin, "{key}").expect("operator key");
    drop(stdin);
    child.wait_with_output().expect("operator output")
}

fn wait_for_clean_exit(mut child: Child) -> Output {
    for _ in 0..10_000 {
        if child.try_wait().expect("node status").is_some() {
            return child.wait_with_output().expect("node output");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = child.kill();
    child.wait_with_output().expect("killed node output")
}

fn run_lifecycle(backend: &str) {
    let database = temporary_path(&format!("{backend}-database"));
    let socket = temporary_path(&format!("{backend}-socket"));
    let key_one = key_hex(0x5a);
    let key_two = key_hex(0x6b);

    let mut created = start_node("create", backend, &database, &socket, &key_one);
    wait_for_socket(&mut created, &socket);
    let wrong_key = run_operator(&socket, 1, &["inspect"], &key_two);
    assert!(!wrong_key.status.success());
    assert!(created.try_wait().expect("node status").is_none());
    let inspect = run_operator(&socket, 1, &["inspect"], &key_one);
    assert!(inspect.status.success(), "{:?}", inspect.stderr);
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("Inspected"));

    let recipient = format!("00{}", "77".repeat(32));
    let account = run_operator(&socket, 2, &["account", &recipient], &key_one);
    assert!(account.status.success(), "{:?}", account.stderr);
    assert!(String::from_utf8_lossy(&account.stdout).contains("exists: false"));

    let malformed = run_operator(&socket, 3, &["submit-tx", "00"], &key_one);
    assert_eq!(malformed.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&malformed.stdout).contains("InvalidTransaction"));

    let shutdown = run_operator(&socket, 4, &["shutdown"], &key_one);
    assert!(shutdown.status.success(), "{:?}", shutdown.stderr);
    assert!(String::from_utf8_lossy(&shutdown.stdout).contains("ShutdownRequested"));
    let created_output = wait_for_clean_exit(created);
    assert!(
        created_output.status.success(),
        "{:?}",
        created_output.stderr
    );
    assert!(!socket.exists());

    let mut reopened = start_node("open", backend, &database, &socket, &key_two);
    wait_for_socket(&mut reopened, &socket);
    let inspect = run_operator(&socket, 1, &["inspect"], &key_two);
    assert!(inspect.status.success(), "{:?}", inspect.stderr);
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("Devnet"));
    let shutdown = run_operator(&socket, 2, &["shutdown"], &key_two);
    assert!(shutdown.status.success(), "{:?}", shutdown.stderr);
    let reopened_output = wait_for_clean_exit(reopened);
    assert!(
        reopened_output.status.success(),
        "{:?}",
        reopened_output.stderr
    );
    assert!(!socket.exists());

    if database.is_dir() {
        fs::remove_dir_all(&database).expect("remove database directory");
    } else {
        fs::remove_file(&database).expect("remove database file");
    }
}

#[test]
fn both_persistent_backends_create_control_shutdown_and_reopen() {
    run_lifecycle("redb");
    run_lifecycle("rocksdb");
}
