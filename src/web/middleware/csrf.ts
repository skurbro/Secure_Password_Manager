import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { logSecurityEvent, SecurityEvent, Outcome } from '../../core/logger';

declare module 'express-session' {
  interface SessionData {
    csrfToken?: string;
  }
}

export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

const HMAC_SECRET = process.env.CSRF_HMAC_SECRET || crypto.randomBytes(32).toString('hex');

export function createSignedCsrfToken(): string {
  const nonce = crypto.randomBytes(32).toString('hex');
  const mac = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
  return `${nonce}.${mac}`;
}

export function verifySignedCsrfToken(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return false;
    const [nonce, mac] = parts;
    const expected = crypto.createHmac('sha256', HMAC_SECRET).update(nonce).digest('hex');
    const a = Buffer.from(mac, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

const EXEMPT_METHODS = ['GET', 'HEAD', 'OPTIONS'];
const EXEMPT_PATHS = ['/api/vault/generate-password'];

function shouldIgnorePath(path: string): boolean {
  return EXEMPT_PATHS.includes(path);
}

function shouldIgnoreMethod(method: string): boolean {
  return EXEMPT_METHODS.includes(method);
}

function extractClientToken(req: Request): string | undefined {
  return (req.headers['x-csrf-token'] || req.headers['X-CSRF-Token'] || req.body?._csrf) as string | undefined;
}

function logDebugInfo(req: Request, clientToken: string | undefined, sessionToken: string | undefined): void {
  if (process.env.DEBUG_CSRF !== '1') return;
  
  try {
    const cookie = req.headers.cookie || '';
    const clientTokenShort = clientToken ? `${clientToken.slice(0,8)}...${clientToken.slice(-8)}` : 'none';
    const sessionTokenShort = sessionToken ? `${sessionToken.slice(0,8)}...${sessionToken.slice(-8)}` : 'none';
    console.log(`[CSRF DEBUG] origin=${req.headers.origin || 'none'} method=${req.method} path=${req.path}`);
    console.log(`[CSRF DEBUG] cookie=${cookie} sessionID=${req.sessionID} sessionTokenPresent=${!!sessionToken}`);
    console.log(`[CSRF DEBUG] clientTokenPresent=${!!clientToken} clientToken=${clientTokenShort} sessionToken=${sessionTokenShort}`);
  } catch (e) {
    console.log('[CSRF DEBUG] logging failure', e);
  }
}

function sendCsrfError(res: Response, message: string, req: Request, userId: string = 'anonymous'): void {
  logSecurityEvent({
    event: SecurityEvent.ACCESS_DENIED,
    userId,
    sessionId: req.sessionID,
    outcome: Outcome.DENIED,
    message,
    metadata: { path: req.path, method: req.method, ip: req.ip },
  });
  res.status(403).json({ error: 'Forbidden', message: 'Invalid or missing CSRF token' });
}

function rotateTokenAndContinue(req: Request, res: Response, next: NextFunction, debugMsg: string): void {
  const newSigned = createSignedCsrfToken();
  req.session.csrfToken = newSigned;
  req.session.save((err) => {
    if (process.env.DEBUG_CSRF === '1') console.log(`[CSRF DEBUG] ${debugMsg}`, err);
    next();
  });
}

function validateSessionToken(clientToken: string, sessionToken: string): boolean {
  try {
    const tokenBuffer = Buffer.from(clientToken);
    const sessionBuffer = Buffer.from(sessionToken);
    if (tokenBuffer.length !== sessionBuffer.length) return false;
    return crypto.timingSafeEqual(tokenBuffer, sessionBuffer);
  } catch {
    return false;
  }
}

function validateCsrfToken(clientToken: string, sessionToken?: string): boolean {
  if (clientToken.includes('.') && verifySignedCsrfToken(clientToken)) {
    return true;
  }
  
  if (sessionToken && validateSessionToken(clientToken, sessionToken)) {
    return true;
  }
  
  return false;
}

export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (shouldIgnoreMethod(req.method) || shouldIgnorePath(req.path)) {
    return next();
  }

  const clientToken = extractClientToken(req);
  const sessionToken = req.session?.csrfToken;

  logDebugInfo(req, clientToken, sessionToken);

  if (!clientToken) {
    sendCsrfError(res, 'CSRF token missing', req, req.session?.userId || 'anonymous');
    return;
  }

  if (validateCsrfToken(clientToken, sessionToken)) {
    rotateTokenAndContinue(req, res, next, 'token verified, rotated');
    return;
  }

  sendCsrfError(res, 'CSRF token invalid', req, req.session?.userId || 'anonymous');
}

export function addCsrfTokenToResponse(req: Request, res: Response, next: NextFunction): void {
  res.header('Access-Control-Allow-Credentials', 'true');
  const originalJson = res.json.bind(res);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  res.json = function (data: any) {
    if (req.session?.csrfToken && typeof data === 'object' && data !== null) data.csrfToken = req.session.csrfToken;
    return originalJson(data);
  };
  next();
}

export function csrfErrorHandler(err: Error, req: Request, res: Response, next: NextFunction): void {
  if (res.headersSent) {
    return next(err);
  }
  next(err);
}

