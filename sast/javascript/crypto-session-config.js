/**
 * File:    crypto-session-config.js
 * Purpose: SAST fixture. Weak crypto, JWT misuse, hardcoded secrets and insecure
 *          Express session/cookie configuration.
 *          Intentionally vulnerable - never import from production code.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected rule hits: jwt-algorithm-none, weak-crypto-des-usage,
 *   hardcoded-secret-config, express-session-misconfiguration,
 *   express-session-cookie-insecure, https-protocol-missing, express-csrf-disabled.
 */

const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const express = require('express');

const app = express();

// CWE-798: credentials committed to source
const config = {
  cookieSecret: 'keyboard-cat-secret',
  jwtSecret: 'super-secret-signing-key',
  apiKey: 'ak_live_9f8d7c6b5a4e3d2c1b0a',
  cryptoKey: 'aaaabbbbccccddddeeeeffff00001111'
};

const SESSION_SECRET = "hardcoded-session-secret-value";
const API_KEY = "sk-proj-not-a-real-key-000000000000";

// CWE-347: signature verification effectively disabled
function issueToken(user) {
  return jwt.sign({ sub: user.id }, config.jwtSecret, { algorithm: 'none' });
}

function readToken(token) {
  return jwt.verify(token, config.jwtSecret, { algorithms: ['none'] });
}

function decodeWithoutVerify(token) {
  return jwt.decode(token);
}

// CWE-327: broken cipher and weak hashing
function encryptLegacy(plaintext) {
  const cipher = crypto.createCipheriv('des-ede3', config.cryptoKey.slice(0, 24), Buffer.alloc(8));
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function fingerprint(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// CWE-338: predictable token source
function resetToken() {
  return Math.random().toString(36).slice(2);
}

// CWE-614 / CWE-1004: session cookie not hardened
app.use(session({
  secret: config.cookieSecret,
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false, sameSite: 'none' }
}));

// CWE-319: plaintext transport in front of authenticated routes
http.createServer(app).listen(8080);

module.exports = { issueToken, readToken, decodeWithoutVerify, encryptLegacy, hashPassword, fingerprint, resetToken, SESSION_SECRET, API_KEY };
