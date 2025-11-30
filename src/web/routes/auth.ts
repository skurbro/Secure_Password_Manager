
import { Router, Request, Response } from 'express';
import {
  isInitialized,
  initializeMasterPassword,
  verifyMasterPassword,
  lockVault,
  validatePasswordStrength,
} from '../../core/auth';
import { secureWipe } from '../../core/memory';
import { logSecurityEvent, SecurityEvent, Outcome } from '../../core/logger';
import { generateCsrfToken, createSignedCsrfToken } from '../middleware/csrf';

const router = Router();

function validateInput(input: unknown, maxLength: number = 1000): string | null {
  if (typeof input !== 'string') {
    return null;
  }
  const sanitized = input.trim().slice(0, maxLength);
  return sanitized.length > 0 ? sanitized : null;
}

router.get('/status', (req: Request, res: Response) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  if (!req.session.csrfToken) {
    req.session.csrfToken = createSignedCsrfToken();
    req.session.save(() => {});
  }
  res.json({ initialized: isInitialized(), authenticated: !!req.session?.isAuthenticated, csrfToken: req.session.csrfToken });
});

router.post('/register', async (req: Request, res: Response) => {
  try {
    if (isInitialized()) {
      res.status(400).json({
        error: 'Already initialized',
        message: 'Vault is already set up. Please login instead.',
      });
      return;
    }

    const password = validateInput(req.body.password, 128);
    if (!password) {
      res.status(400).json({
        error: 'Invalid input',
        message: 'Password is required',
      });
      return;
    }

    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
      res.status(400).json({
        error: 'Weak password',
        message: strengthCheck.errors.join('. '),
      });
      return;
    }

    const result = await initializeMasterPassword(password);

    if (!result.success) {
      res.status(400).json({
        error: 'Registration failed',
        message: result.message,
      });
      return;
    }

    req.session.userId = result.userId;
    req.session.derivedKey = result.derivedKey?.toString('base64');
    req.session.isAuthenticated = true;
    req.session.createdAt = Date.now();
    const signed = createSignedCsrfToken();
    req.session.csrfToken = signed;

    logSecurityEvent({
      event: SecurityEvent.MASTER_PASSWORD_CREATED,
      userId: result.userId,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Vault initialized via web',
      metadata: { ip: req.ip },
    });
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        res.status(500).json({ error: 'Session error', message: 'Failed to save session' });
        return;
      }
      res.header('Access-Control-Allow-Credentials', 'true');
      res.status(201).json({ success: true, message: 'Vault created successfully', csrfToken: signed });
    });
  } catch (error) {
    res.status(500).json({
      error: 'Registration failed',
      message: 'An unexpected error occurred',
    });
  }
});

router.post('/login', async (req: Request, res: Response) => {
  try {
    if (!isInitialized()) {
      res.status(400).json({
        error: 'Not initialized',
        message: 'Vault is not set up. Please register first.',
      });
      return;
    }

    if (req.session?.isAuthenticated) {
      res.json({
        success: true,
        message: 'Already authenticated',
        csrfToken: req.session.csrfToken,
      });
      return;
    }

    const password = validateInput(req.body.password, 128);
    if (!password) {
      logSecurityEvent({
        event: SecurityEvent.LOGIN_FAILURE,
        userId: 'unknown',
        sessionId: req.sessionID,
        outcome: Outcome.FAILURE,
        message: 'Login attempt with empty password',
        metadata: { ip: req.ip },
      });

      res.status(400).json({
        error: 'Invalid input',
        message: 'Password is required',
      });
      return;
    }

    const result = await verifyMasterPassword(password);

    if (!result.success) {
      logSecurityEvent({
        event: SecurityEvent.LOGIN_FAILURE,
        userId: 'unknown',
        sessionId: req.sessionID,
        outcome: Outcome.FAILURE,
        message: 'Invalid master password',
        metadata: { ip: req.ip },
      });

      res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid master password',
      });
      return;
    }

    req.session.userId = result.userId;
    req.session.derivedKey = result.derivedKey?.toString('base64');
    req.session.isAuthenticated = true;
    req.session.createdAt = Date.now();
    const signed = createSignedCsrfToken();
    req.session.csrfToken = signed;

    logSecurityEvent({
      event: SecurityEvent.LOGIN_SUCCESS,
      userId: result.userId,
      sessionId: req.sessionID,
      outcome: Outcome.SUCCESS,
      message: 'Login via web',
      metadata: { ip: req.ip },
    });
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        res.status(500).json({ error: 'Session error', message: 'Failed to save session' });
        return;
      }
      res.header('Access-Control-Allow-Credentials', 'true');
      res.json({ success: true, message: 'Login successful', csrfToken: signed });
    });
  } catch (error) {
    res.status(500).json({
      error: 'Login failed',
      message: 'An unexpected error occurred',
    });
  }
});

router.post('/logout', (req: Request, res: Response): void => {
  const userId = req.session?.userId;
  if (req.session?.derivedKey) secureWipe(Buffer.from(req.session.derivedKey, 'base64'));
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Logout failed', message: 'Failed to destroy session' });
      return;
    }
    res.clearCookie('spm_session');
    lockVault();
    if (userId) logSecurityEvent({ event: SecurityEvent.LOGOUT, userId, outcome: Outcome.SUCCESS, message: 'Logout via web', metadata: { ip: req.ip } });
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

router.get('/check', (req: Request, res: Response) => {
  if (req.session?.isAuthenticated) return res.json({ authenticated: true, userId: req.session.userId });
  return res.json({ authenticated: false });
});

export { router as authRouter };

