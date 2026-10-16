// File:    vulnerable.rs
// Purpose: SAST fixture. Rust command injection, SQL injection, unsafe blocks,
//          weak crypto, disabled TLS verification and embedded credentials.
//          Intentionally vulnerable - never link into production code.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
//
// Expected CWEs: 78, 89, 119, 327, 295, 798, 338, 22, 918.

use std::fs;
use std::process::Command;
use std::ptr;

use md5::Digest;
use sha1::Sha1;

// CWE-798: credentials in source
const API_KEY: &str = "ak_live_rust_0123456789abcdef";
const DB_PASSWORD: &str = "Pr0dPassw0rd!";

// CWE-78: command injection
pub fn ping(host: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", host))
        .output()
}

pub fn archive(dir: &str) -> std::io::Result<std::process::Output> {
    Command::new("bash")
        .arg("-c")
        .arg(format!("tar -czf /tmp/out.tgz {}", dir))
        .output()
}

// CWE-89: SQL injection through format!
pub fn find_user_query(email: &str) -> String {
    format!("SELECT id, email FROM users WHERE email = '{}'", email)
}

pub async fn find_user(pool: &sqlx::PgPool, email: &str) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error> {
    let sql = format!("SELECT id, email FROM users WHERE email = '{}'", email);
    sqlx::query(&sql).fetch_all(pool).await
}

// CWE-22: path traversal
pub fn read_report(name: &str) -> std::io::Result<Vec<u8>> {
    fs::read(format!("/srv/files/{}", name))
}

// CWE-327: broken hashes
pub fn hash_password(password: &str) -> String {
    format!("{:x}", md5::Md5::digest(password.as_bytes()))
}

pub fn fingerprint(data: &[u8]) -> String {
    format!("{:x}", Sha1::digest(data))
}

// CWE-295: TLS verification disabled
pub fn insecure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("client build failed")
}

// CWE-918: SSRF
pub async fn proxy(url: &str) -> Result<String, reqwest::Error> {
    insecure_client().get(url).send().await?.text().await
}

// CWE-119 / CWE-476: unchecked raw pointer work
pub unsafe fn copy_raw(src: *const u8, len: usize) -> Vec<u8> {
    let mut dst = Vec::with_capacity(len);
    ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), len);
    dst.set_len(len);
    dst
}

pub unsafe fn deref_null() -> u8 {
    let p: *const u8 = ptr::null();
    *p
}

// CWE-676: panics on attacker-controlled input
pub fn parse_id(raw: &str) -> u64 {
    raw.parse::<u64>().unwrap()
}

pub fn slice_prefix(data: &[u8], n: usize) -> &[u8] {
    &data[..n]
}
