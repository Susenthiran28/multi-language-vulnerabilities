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

function safeEvaluateArithmetic(expr: string): number {
  if (!/^[0-9+\-*/().\s]+$/.test(expr)) {
    throw new Error('Invalid expression');
  }

  const tokens = expr.match(/\d*\.?\d+|[()+\-*/]/g);
  if (!tokens || tokens.length === 0) {
    throw new Error('Invalid expression');
  }

  let i = 0;

  const parseExpression = (): number => {
    let value = parseTerm();
    while (i < tokens.length && (tokens[i] === '+' || tokens[i] === '-')) {
      const op = tokens[i++];
      const rhs = parseTerm();
      value = op === '+' ? value + rhs : value - rhs;
    }
    return value;
  };

  const parseTerm = (): number => {
    let value = parseFactor();
    while (i < tokens.length && (tokens[i] === '*' || tokens[i] === '/')) {
      const op = tokens[i++];
      const rhs = parseFactor();
      if (op === '/' && rhs === 0) {
        throw new Error('Invalid expression');
      }
      value = op === '*' ? value * rhs : value / rhs;
    }
    return value;
  };

  const parseFactor = (): number => {
    if (i >= tokens.length) {
      throw new Error('Invalid expression');
    }

    const token = tokens[i++];

    if (token === '(') {
      const value = parseExpression();
      if (i >= tokens.length || tokens[i] !== ')') {
        throw new Error('Invalid expression');
      }
      i++;
      return value;
    }

    const num = Number(token);
    if (!Number.isFinite(num)) {
      throw new Error('Invalid expression');
    }
    return num;
  };

  const result = parseExpression();
  if (i !== tokens.length || !Number.isFinite(result)) {
    throw new Error('Invalid expression');
  }

  return result;
}

export function evaluate(req: Request, res: Response): void {
  const expr = req.query.expr;
  if (typeof expr !== 'string' || expr.trim() === '') {
    res.status(400).json({ error: 'Invalid expression' });
    return;
  }

  try {
    const value = safeEvaluateArithmetic(expr);
    res.json({ value });
  } catch {
    res.status(400).json({ error: 'Invalid expression' });
  }
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
