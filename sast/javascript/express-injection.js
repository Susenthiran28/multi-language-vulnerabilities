/**
 * File:    express-injection.js
 * Purpose: SAST fixture. Express handlers carrying injection-class defects
 *          (eval, command, SQL, NoSQL, path traversal, SSRF, open redirect).
 *          Intentionally vulnerable - never import from production code.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected rule hits: eval-with-user-input, eval-user-input-express,
 *   function-constructor-with-user-input, command-injection-exec-user-input,
 *   sql-injection-string-concat, javascript-express-nosql-injection,
 *   path-traversal-user-input, ssrf-user-url, express-open-redirect.
 */

const express = require('express');
const fs = require('fs');
const https = require('https');
const axios = require('axios');
const { exec, execSync } = require('child_process');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

// CWE-95: eval on request-controlled data
app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.json({ result });
});

app.post('/render', (req, res) => {
  const tpl = new Function(req.body.template);
  res.send(tpl());
});

// CWE-78: OS command injection
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout));
});

app.get('/archive', (req, res) => {
  const out = execSync(`tar -czf /tmp/out.tgz ${req.query.dir}`);
  res.send(out.toString());
});

// CWE-89: SQL injection via concatenation
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query, (err, rows) => res.json(rows));
});

// CWE-943: NoSQL injection - request body flows straight into the filter
app.post('/search', async (req, res) => {
  const collection = req.app.locals.db.collection('users');
  const docs = await collection.find(req.body.filter).toArray();
  res.json(docs);
});

app.post('/where', async (req, res) => {
  const collection = req.app.locals.db.collection('users');
  const docs = await collection.find({ $where: `this.name === '${req.body.name}'` }).toArray();
  res.json(docs);
});

// CWE-22: path traversal
app.get('/download', (req, res) => {
  const body = fs.readFileSync(req.query.path);
  res.send(body);
});

app.get('/static', (req, res) => {
  res.sendFile(req.params.file);
});

// CWE-918: SSRF
app.get('/proxy', async (req, res) => {
  const upstream = await axios.get(req.query.url);
  res.json(upstream.data);
});

app.get('/fetch', (req, res) => {
  https.get(req.query.target, (upstream) => upstream.pipe(res));
});

// CWE-601: open redirect
app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

module.exports = app;
