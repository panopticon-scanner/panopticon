use chrono::Local;
use regex::Regex;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// Deliberately flawed Rust fixture for static analysis validation.
// It compiles and runs, but contains common CWE/OWASP patterns.

static API_KEY: &str = "hardcoded-secret-key-12345";
static PASSWORD: &str = "admin:password123";
static SECRET_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// CWE-307: Improper restriction of excessive authentication attempts.
// No rate limiting, account lockout, or exponential back-off.
fn insecure_login(username: &str, password: &str) -> bool {
    // CWE-208: Observable timing discrepancy in password comparison.
    if username == "admin" && password == PASSWORD {
        return true;
    }
    false
}

// OWASP A07 / CWE-640: Weak password recovery / predictable token generation.
fn weak_random_token() -> u64 {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    seed.wrapping_mul(1103515245).wrapping_add(12345)
}

// OWASP A01 / CWE-284: Missing authorization check (broken access control).
fn fetch_admin_data(_role: &str) -> String {
    // The role parameter is ignored; any caller can retrieve admin data.
    "admin secrets".to_string()
}

// OWASP A05 / CWE-209: Security misconfiguration via verbose debug endpoint.
fn debug_mode_leak() -> String {
    format!(
        "debug=true; env={:?}; token={}",
        env::vars().collect::<HashMap<_, _>>(),
        SECRET_TOKEN
    )
}

// OWASP A09 / CWE-778: Security logging and monitoring failures.
// Sensitive actions are performed without any audit trail.
fn sensitive_action_without_logging(action: &str) {
    if action == "transfer" {
        println!("transferred funds");
    }
}

fn run(user_input: &str) {
    // CWE-78: Command injection via unsanitized user input.
    let output = Command::new("sh")
        .arg("-c")
        .arg(&user_input)
        .output()
        .expect("command failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // CWE-22: Path traversal via unsanitized file path.
    let contents = fs::read_to_string(&user_input).unwrap_or_default();
    println!("file contents: {}", contents);

    // CWE-89: SQL injection via string concatenation.
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
    println!("query: {}", query);

    // CWE-502: Insecure deserialization of untrusted CBOR/YAML input.
    let _value: serde_cbor::Value = serde_cbor::from_slice(user_input.as_bytes()).unwrap();
    let _yaml: serde_yaml::Value = serde_yaml::from_str(user_input).unwrap();

    // CWE-798: Hardcoded credentials.
    println!("api key: {}", API_KEY);
    println!("password: {}", PASSWORD);

    // CWE-400: Uncontrolled resource consumption / panic on malformed input.
    let number: i32 = user_input.parse().unwrap();
    println!("parsed {}", number);

    // CWE-326 / CWE-327: Weak hashing (MD5-like custom checksum, no salt).
    let mut hash: u32 = 0;
    for byte in user_input.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    println!("hash: {}", hash);

    // CWE-200: Information exposure through verbose error message.
    if let Err(e) = fs::read_to_string("/etc/shadow") {
        eprintln!("detailed internal error: {:?}", e);
    }

    // CWE-119 / CWE-787: Unsafe memory access and vulnerable smallvec usage.
    let mut buf = [0u8; 8];
    unsafe {
        let ptr = buf.as_mut_ptr();
        for i in 0..user_input.len() {
            *ptr.add(i) = user_input.as_bytes()[i];
        }
    }
    println!("buffer: {:?}", buf);
    let mut small: SmallVec<[u8; 4]> = SmallVec::new();
    for byte in user_input.bytes() {
        small.push(byte);
    }
    println!("smallvec: {:?}", small);

    // CWE-912: Hidden functionality / backdoor (deliberately obvious).
    if user_input == "debug_backdoor_please" {
        println!("backdoor activated");
    }

    // CWE-347 / CWE-918: Missing authentication / SSRF-like fetch.
    if user_input.starts_with("http") {
        println!("would fetch: {}", user_input);
    }

    // CWE-307 / OWASP A07: Brute-force vulnerable login and predictable tokens.
    let _ = insecure_login(user_input, PASSWORD);
    println!("token: {}", weak_random_token());

    // OWASP A01: Broken access control — no authorization check.
    println!("admin data: {}", fetch_admin_data(user_input));

    // OWASP A05: Security misconfiguration / verbose debug leak.
    println!("debug info: {}", debug_mode_leak());

    // OWASP A09: Missing security logging for sensitive action.
    sensitive_action_without_logging(user_input);

    // CWE-476: NULL pointer dereference risk via unwrap.
    let first_arg = env::args().nth(1).unwrap();
    println!("first arg: {}", first_arg);

    // Deprecated/unsound API usage.
    let _now = time::now();
    let _dt = Local::now();

    // CWE-1333 / OWASP A03: Inefficient regex (ReDoS) via user-controlled pattern.
    let re = Regex::new(user_input).unwrap();
    println!("regex match: {}", re.is_match("hello world"));
}

fn main() {
    let user_input = env::args().nth(1).unwrap_or_default();
    run(&user_input);
}
