/**
 * File:    hardcoded.js
 * Purpose: Secret-scanner fixture. Credentials embedded in JavaScript source,
 *          confirming the detector works inside code and not only in .env files.
 *          All values are synthetic and non-functional.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 */

const config = {
  openaiApiKey: 'sk-proj-FIXTURE00000000000000000000000000000000000000000',
  stripeSecret: 'sk_live_FIXTURE0000000000000000000000',
  githubToken: 'ghp_FIXTURE00000000000000000000000000000',
  npmToken: 'npm_FIXTURE000000000000000000000000000000',
  mongoUri: 'mongodb://appuser:FixturePassw0rd@db.internal.example.com:27017/app',
  jwtSecret: 'fixture-jwt-signing-secret-000000000000',
  encryptionKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
};

const SLACK_WEBHOOK = 'https://hooks.slack.com/services/T00000000/B00000000/FIXTURE000000000000000000';
const BASIC_AUTH = 'Basic ZGVwbG95OkZpeHR1cmVEZXBsb3lUb2tlbg==';
const SESSION_SECRET = 'fixture-session-secret-value-0000000000';

module.exports = { config, SLACK_WEBHOOK, BASIC_AUTH, SESSION_SECRET };
