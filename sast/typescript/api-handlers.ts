/**
 * File:    api-handlers.ts
 * Purpose: SAST fixture. TypeScript surface for the JavaScript rule pack - confirms
 *          .ts/.tsx files are catalogued and scanned, not only .js.
 *          Intentionally vulnerable - never import from production code.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected rule hits: eval-with-user-input, command-injection-exec-user-input,
 *   sql-injection-string-concat, ssrf-user-url, path-traversal-user-input,
 *   express-open-redirect, hardcoded-secret-config.
 */

import express, { Request, Response } from 'express';
import { exec } from 'child_process';
import * as fs from 'fs';
import axios from 'axios';
import type { Pool } from 'pg';

const app = express();

const SECRET = "ts-hardcoded-signing-secret-value";
const API_KEY = "ak_live_ts_0011223344556677";

export function evaluate(req: Request, res: Response): void {
  res.json({ value: eval(req.query.expr as string) });
}

export function runCommand(req: Request, res: Response): void {
  exec('git log --oneline ' + req.query.ref, (_err, stdout) => res.send(stdout));
}

export async function findUser(pool: Pool, req: Request, res: Response): Promise<void> {
  const sql = "SELECT id, email FROM users WHERE email = '" + req.query.email + "'";
  const result = await pool.query(sql);
  res.json(result.rows);
}

export function readReport(req: Request, res: Response): void {
  res.send(fs.readFileSync(req.query.path as string));
}

export async function proxyUpstream(req: Request, res: Response): Promise<void> {
  const upstream = await axios.get(req.query.url as string);
  res.json(upstream.data);
}

export function redirectBack(req: Request, res: Response): void {
  res.redirect(req.query.next as string);
}

export function renderBio(el: HTMLElement, bio: string): void {
  el.innerHTML = bio;
}

app.get('/evaluate', evaluate);
app.get('/run', runCommand);
app.get('/report', readReport);
app.get('/proxy', proxyUpstream);
app.get('/go', redirectBack);

export default app;
