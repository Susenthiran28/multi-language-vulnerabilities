// File:    hardcoded.rs
// Purpose: Secret-scanner fixture. Credentials embedded in Rust source.
//          All values are synthetic and non-functional.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16

pub const OPENAI_API_KEY: &str = "sk-proj-FIXTURE00000000000000000000000000000000000000000";
pub const GITHUB_PAT: &str = "ghp_FIXTURE00000000000000000000000000000";
pub const AWS_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
pub const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
pub const DATABASE_URL: &str = "postgresql://appuser:FixturePassw0rd@db.internal.example.com:5432/app";
pub const ENCRYPTION_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const DB_PASSWORD: &str = "FixturePassw0rd";
