
import { Request, Response, NextFunction } from 'express';
import { logSecurityEvent, SecurityEvent, Outcome } from '../../core/logger';

const SESSION_TIMEOUT = 15 * 60 * 1000;

export interface AuthenticatedRequest extends Request {
  userId?: string;
  derivedKey?: Buffer;
}

export function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  res.header('Access-Control-Allow-Credentials', 'true');
  if (!req.session || !req.session.isAuthenticated) {
    logSecurityEvent({
      event: SecurityEvent.ACCESS_DENIED,
      userId: 'anonymous',
      sessionId: req.sessionID,
      outcome: Outcome.DENIED,
      message: 'Unauthenticated access attempt',
      metadata: {
        path: req.path,
        method: req.method,
        ip: req.ip,
      },
    });

    res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  const sessionAge = Date.now() - (req.session.createdAt || 0);
  if (sessionAge > SESSION_TIMEOUT) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
    });

    logSecurityEvent({
      event: SecurityEvent.SESSION_TIMEOUT,
      userId: req.session.userId || 'unknown',
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Session expired',
    });

    res.status(401).json({
      error: 'Session expired',
      message: 'Your session has expired. Please log in again.',
    });
    return;
  }

  if (!req.session.userId || !req.session.derivedKey) {
    res.status(401).json({
      error: 'Invalid session',
      message: 'Session data is incomplete. Please log in again.',
    });
    return;
  }

  req.userId = req.session.userId;

  try {
    req.derivedKey = Buffer.from(req.session.derivedKey, 'base64');
  } catch (error) {
    res.status(401).json({
      error: 'Invalid session',
      message: 'Session data is corrupted. Please log in again.',
    });
    return;
  }

  req.session.createdAt = Date.now();
  
  if (!req.session.isAuthenticated) {
    req.session.isAuthenticated = true;
  }

  next();
}

export function optionalAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  if (req.session?.isAuthenticated && req.session.userId && req.session.derivedKey) {
    req.userId = req.session.userId;
    try {
      req.derivedKey = Buffer.from(req.session.derivedKey, 'base64');
    } catch (error) {
    }
  }
  next();
}

