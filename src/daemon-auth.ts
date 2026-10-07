/**
 * Daemon pairing token: a high-entropy secret shared between the CLI and the
 * daemon's HTTP /command endpoint, generated on first use and stored under
 * USER_OPENCLI_DIR with owner-only permissions.
 *
 * Replaces the previous "X-OpenCLI: 1" constant-value header check, which
 * was not a credential at all (any local process, not just a browser bound
 * by CORS, could send the identical literal value and dispatch arbitrary
 * browser-automation commands).
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { USER_OPENCLI_DIR } from './discovery.js';

const TOKEN_FILE = path.join(USER_OPENCLI_DIR, 'daemon.token');
const TOKEN_BYTES = 32;

/** Read the existing daemon pairing token, generating and persisting one if absent. */
export function getOrCreateDaemonToken(): string {
  try {
    const existing = fs.readFileSync(TOKEN_FILE, 'utf-8').trim();
    if (existing) return existing;
  } catch {
    // File missing or unreadable — fall through to generate a new one.
  }
  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  fs.mkdirSync(USER_OPENCLI_DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, token, { mode: 0o600 });
  // Some filesystems (or an already-existing file with looser permissions
  // from before this fix) don't honor the mode on writeFileSync; enforce it.
  try { fs.chmodSync(TOKEN_FILE, 0o600); } catch { /* best-effort on platforms without chmod */ }
  return token;
}

/** Constant-time comparison of a request-supplied header value against the real token. */
export function isValidDaemonToken(headerValue: unknown, expected: string): boolean {
  if (typeof headerValue !== 'string' || !headerValue) return false;
  const a = Buffer.from(headerValue, 'utf-8');
  const b = Buffer.from(expected, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
