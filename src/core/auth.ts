import * as argon2 from 'argon2';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { secureWipe, stringToSecureBuffer } from './memory';
import { deriveKey, generateSalt } from './crypto';
import { logSecurityEvent, SecurityEvent, Outcome, logError } from './logger';

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 4,
  parallelism: 2,
  hashLength: 64,
  raw: false as const,
};

const CONFIG_DIR = process.env.DB_PATH
  ? path.dirname(process.env.DB_PATH)
  : path.join(process.cwd(), '.vault');
const AUTH_CONFIG_FILE = path.join(CONFIG_DIR, 'auth.json');
interface AuthConfig {
  userId: string;
  passwordHash: string;
  salt: string;
  keySalt: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface AuthResult {
  success: boolean;
  userId: string;
  sessionId: string;
  derivedKey?: Buffer;
  message: string;
}

class SessionManager {
  private currentSession: {
    userId: string;
    sessionId: string;
    derivedKey: Buffer | null;
    createdAt: Date;
    lastActivity: Date;
  } | null = null;

  private readonly sessionTimeout = 15 * 60 * 1000;

  createSession(userId: string, derivedKey: Buffer): { sessionId: string; derivedKey: Buffer } {
    this.endSession();

    const sessionId = crypto.randomUUID();
    this.currentSession = {
      userId,
      sessionId,
      derivedKey,
      createdAt: new Date(),
      lastActivity: new Date(),
    };

    return { sessionId, derivedKey };
  }

  getSession(): { userId: string; sessionId: string; derivedKey: Buffer } | null {
    if (!this.currentSession || !this.currentSession.derivedKey) {
      return null;
    }

    const now = new Date();
    const timeSinceLastActivity = now.getTime() - this.currentSession.lastActivity.getTime();

    if (timeSinceLastActivity > this.sessionTimeout) {
      logSecurityEvent({
        event: SecurityEvent.SESSION_TIMEOUT,
        userId: this.currentSession.userId,
        sessionId: this.currentSession.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Session timed out due to inactivity',
      });
      this.endSession();
      return null;
    }

    this.currentSession.lastActivity = now;

    return {
      userId: this.currentSession.userId,
      sessionId: this.currentSession.sessionId,
      derivedKey: this.currentSession.derivedKey,
    };
  }

  endSession(): void {
    if (this.currentSession) {
      if (this.currentSession.derivedKey) {
        secureWipe(this.currentSession.derivedKey);
      }

      logSecurityEvent({
        event: SecurityEvent.LOGOUT,
        userId: this.currentSession.userId,
        sessionId: this.currentSession.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Session ended',
      });

      this.currentSession = null;
    }
  }

  hasActiveSession(): boolean {
    return this.getSession() !== null;
  }
}

const sessionManager = new SessionManager();

function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

export function isInitialized(): boolean {
  return fs.existsSync(AUTH_CONFIG_FILE);
}

function loadAuthConfig(): AuthConfig | null {
  try {
    if (!fs.existsSync(AUTH_CONFIG_FILE)) {
      return null;
    }
    const data = fs.readFileSync(AUTH_CONFIG_FILE, 'utf8');
    return JSON.parse(data) as AuthConfig;
  } catch (error) {
    logError('Failed to load auth config', error as Error);
    return null;
  }
}

function saveAuthConfig(config: AuthConfig): void {
  ensureConfigDir();
  fs.writeFileSync(AUTH_CONFIG_FILE, JSON.stringify(config, null, 2), {
    mode: 0o600,
  });
}

export function validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export async function initializeMasterPassword(masterPassword: string): Promise<AuthResult> {
  const userId = crypto.randomUUID();

  try {
    if (isInitialized()) {
      return {
        success: false,
        userId: '',
        sessionId: '',
        message: 'Password manager is already initialized',
      };
    }

    const validation = validatePasswordStrength(masterPassword);
    if (!validation.valid) {
      logSecurityEvent({
        event: SecurityEvent.INVALID_INPUT,
        userId,
        outcome: Outcome.FAILURE,
        message: 'Master password does not meet strength requirements',
      });
      return {
        success: false,
        userId: '',
        sessionId: '',
        message: validation.errors.join('. '),
      };
    }

    const passwordBuffer = stringToSecureBuffer(masterPassword);

    try {
      const keySalt = generateSalt();

      const hash = await argon2.hash(passwordBuffer, ARGON2_CONFIG);

      const config: AuthConfig = {
        userId,
        passwordHash: hash,
        salt: '',
        keySalt: keySalt.toString('base64'),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: 1,
      };

      saveAuthConfig(config);

      const derivedKey = await deriveKey(passwordBuffer, keySalt);

      const session = sessionManager.createSession(userId, derivedKey);

      logSecurityEvent({
        event: SecurityEvent.MASTER_PASSWORD_CREATED,
        userId,
        sessionId: session.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Master password initialized successfully',
      });

      return {
        success: true,
        userId,
        sessionId: session.sessionId,
        derivedKey: session.derivedKey,
        message: 'Password manager initialized successfully',
      };
    } finally {
      secureWipe(passwordBuffer);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error('Init error:', errorMessage);

    logSecurityEvent({
      event: SecurityEvent.MASTER_PASSWORD_CREATED,
      userId,
      outcome: Outcome.ERROR,
      message: `Failed to initialize master password: ${errorMessage}`,
    });

    return {
      success: false,
      userId: '',
      sessionId: '',
      message: `Failed to initialize password manager: ${errorMessage}`,
    };
  }
}

export async function verifyMasterPassword(masterPassword: string): Promise<AuthResult> {
  try {
    const config = loadAuthConfig();
    if (!config) {
      return {
        success: false,
        userId: '',
        sessionId: '',
        message: 'Password manager is not initialized',
      };
    }

    const userId = config.userId || crypto.randomUUID();

    const passwordBuffer = stringToSecureBuffer(masterPassword);

    try {
      const isValid = await argon2.verify(config.passwordHash, passwordBuffer);

      if (!isValid) {
        logSecurityEvent({
          event: SecurityEvent.LOGIN_FAILURE,
          userId,
          outcome: Outcome.FAILURE,
          message: 'Invalid master password',
        });

        return {
          success: false,
          userId: '',
          sessionId: '',
          message: 'Invalid master password',
        };
      }

      const keySalt = Buffer.from(config.keySalt, 'base64');
      const derivedKey = await deriveKey(passwordBuffer, keySalt);

      const session = sessionManager.createSession(userId, derivedKey);

      logSecurityEvent({
        event: SecurityEvent.LOGIN_SUCCESS,
        userId,
        sessionId: session.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Login successful',
      });

      return {
        success: true,
        userId,
        sessionId: session.sessionId,
        derivedKey: session.derivedKey,
        message: 'Authentication successful',
      };
    } finally {
      secureWipe(passwordBuffer);
    }
  } catch (error) {
    logSecurityEvent({
      event: SecurityEvent.LOGIN_FAILURE,
      userId: 'unknown',
      outcome: Outcome.ERROR,
      message: 'Authentication error',
    });

    return {
      success: false,
      userId: '',
      sessionId: '',
      message: 'Authentication failed',
    };
  }
}

export async function changeMasterPassword(
  currentPassword: string,
  newPassword: string
): Promise<AuthResult> {
  const session = sessionManager.getSession();
  const userId = session?.userId || crypto.randomUUID();

  try {
    const config = loadAuthConfig();
    if (!config) {
      return {
        success: false,
        userId: '',
        sessionId: '',
        message: 'Password manager is not initialized',
      };
    }

    const currentPasswordBuffer = stringToSecureBuffer(currentPassword);
    const newPasswordBuffer = stringToSecureBuffer(newPassword);

    try {
      const isValid = await argon2.verify(config.passwordHash, currentPasswordBuffer);
      if (!isValid) {
        logSecurityEvent({
          event: SecurityEvent.MASTER_PASSWORD_CHANGED,
          userId,
          outcome: Outcome.FAILURE,
          message: 'Current password verification failed',
        });

        return {
          success: false,
          userId: '',
          sessionId: '',
          message: 'Current password is incorrect',
        };
      }

      const validation = validatePasswordStrength(newPassword);
      if (!validation.valid) {
        return {
          success: false,
          userId: '',
          sessionId: '',
          message: validation.errors.join('. '),
        };
      }

      const newKeySalt = generateSalt();

      const newHash = await argon2.hash(newPasswordBuffer, ARGON2_CONFIG);

      config.passwordHash = newHash;
      config.salt = '';
      config.keySalt = newKeySalt.toString('base64');
      config.updatedAt = new Date().toISOString();

      saveAuthConfig(config);

      const derivedKey = await deriveKey(newPasswordBuffer, newKeySalt);

      sessionManager.endSession();
      const newSession = sessionManager.createSession(userId, derivedKey);

      logSecurityEvent({
        event: SecurityEvent.MASTER_PASSWORD_CHANGED,
        userId,
        sessionId: newSession.sessionId,
        outcome: Outcome.SUCCESS,
        message: 'Master password changed successfully',
      });

      return {
        success: true,
        userId,
        sessionId: newSession.sessionId,
        derivedKey: newSession.derivedKey,
        message: 'Password changed successfully',
      };
    } finally {
      secureWipe(currentPasswordBuffer);
      secureWipe(newPasswordBuffer);
    }
  } catch (error) {
    logSecurityEvent({
      event: SecurityEvent.MASTER_PASSWORD_CHANGED,
      userId,
      outcome: Outcome.ERROR,
      message: 'Failed to change master password',
    });

    return {
      success: false,
      userId: '',
      sessionId: '',
      message: 'Failed to change password',
    };
  }
}

export function getCurrentSession(): { userId: string; sessionId: string; derivedKey: Buffer } | null {
  return sessionManager.getSession();
}

export function lockVault(): void {
  const session = sessionManager.getSession();
  if (session) {
    logSecurityEvent({
      event: SecurityEvent.VAULT_LOCKED,
      userId: session.userId,
      sessionId: session.sessionId,
      outcome: Outcome.SUCCESS,
      message: 'Vault locked',
    });
  }
  sessionManager.endSession();
}

export function isVaultUnlocked(): boolean {
  return sessionManager.hasActiveSession();
}

export { sessionManager };

