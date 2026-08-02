use std::env;
use std::process::Command;

// Deliberately flawed Rust fixture for static analysis validation.

static API_KEY: &str = "hardcoded-secret-key-12345";

fn main() {
    let user_input = env::args().nth(1).unwrap_or_default();

    // Vulnerable: command injection via unsanitized user input.
    let output = Command::new("sh")
        .arg("-c")
        .arg(&user_input)
        .output()
        .expect("command failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Vulnerable: panic on malformed input (denial of service).
    let number: i32 = user_input.parse().unwrap();
    println!("parsed {}", number);

    // Vulnerable: use of deprecated/unsound crate API.
    let _now = time::now();

    // Vulnerable: hardcoded credential exposure.
    println!("api key: {}", API_KEY);
}
