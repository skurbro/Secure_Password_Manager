
import winston from 'winston';
import * as path from 'path';
import * as fs from 'fs';

const LOG_DIR = path.join(process.cwd(), 'logs');

if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

const structuredFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  winston.format.errors({ stack: false }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, event, userId, outcome }) => {
    let logMessage = `${timestamp} [${level}]: ${message}`;
    if (event) logMessage += ` | Event: ${event}`;
    if (userId) logMessage += ` | User: ${userId}`;
    if (outcome) logMessage += ` | Outcome: ${outcome}`;
    return logMessage;
  })
);

const logger = winston.createLogger({
  levels: logLevels,
  level: process.env.LOG_LEVEL || 'info',
  format: structuredFormat,
  transports: [
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'app.log'),
      maxsize: 5242880,
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'error.log'),
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'security.log'),
      maxsize: 5242880,
      maxFiles: 10,
    }),
  ],
});

if (process.env.LOG_TO_CONSOLE === 'true') {
  logger.add(
    new winston.transports.Console({
      format: consoleFormat,
    })
  );
}

export enum SecurityEvent {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  MASTER_PASSWORD_CREATED = 'MASTER_PASSWORD_CREATED',
  MASTER_PASSWORD_CHANGED = 'MASTER_PASSWORD_CHANGED',
  RECORD_ADDED = 'RECORD_ADDED',
  RECORD_UPDATED = 'RECORD_UPDATED',
  RECORD_DELETED = 'RECORD_DELETED',
  RECORD_VIEWED = 'RECORD_VIEWED',
  PASSWORD_GENERATED = 'PASSWORD_GENERATED',
  EXPORT_ATTEMPTED = 'EXPORT_ATTEMPTED',
  IMPORT_ATTEMPTED = 'IMPORT_ATTEMPTED',
  SESSION_TIMEOUT = 'SESSION_TIMEOUT',
  INVALID_INPUT = 'INVALID_INPUT',
  ACCESS_DENIED = 'ACCESS_DENIED',
  ENCRYPTION_ERROR = 'ENCRYPTION_ERROR',
  DECRYPTION_ERROR = 'DECRYPTION_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  VAULT_LOCKED = 'VAULT_LOCKED',
  VAULT_UNLOCKED = 'VAULT_UNLOCKED',
}

export enum Outcome {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE',
  ERROR = 'ERROR',
  DENIED = 'DENIED',
}

interface LogEntry {
  event: SecurityEvent;
  userId?: string;
  sessionId?: string;
  outcome: Outcome;
  message?: string;
  metadata?: Record<string, unknown>;
}

const SENSITIVE_FIELDS = [
  'password',
  'masterPassword',
  'key',
  'derivedKey',
  'encryptionKey',
  'token',
  'secret',
  'credential',
  'plaintext',
  'decrypted',
  'hash',
  'salt',
  'iv',
  'authTag',
];

function sanitizeForLogging(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      sanitized[key] = sanitizeForLogging(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

export function logSecurityEvent(entry: LogEntry): void {
  const sanitizedMetadata = entry.metadata ? sanitizeForLogging(entry.metadata) : undefined;

  const logData = {
    event: entry.event,
    userId: entry.userId || 'anonymous',
    sessionId: entry.sessionId || 'none',
    outcome: entry.outcome,
    message: entry.message,
    ...sanitizedMetadata,
  };

  switch (entry.outcome) {
    case Outcome.ERROR:
      logger.error(entry.message || entry.event, logData);
      break;
    case Outcome.FAILURE:
    case Outcome.DENIED:
      logger.warn(entry.message || entry.event, logData);
      break;
    default:
      logger.info(entry.message || entry.event, logData);
  }
}

export function logInfo(message: string, metadata?: Record<string, unknown>): void {
  const sanitized = metadata ? sanitizeForLogging(metadata) : {};
  logger.info(message, sanitized);
}

export function logWarning(message: string, metadata?: Record<string, unknown>): void {
  const sanitized = metadata ? sanitizeForLogging(metadata) : {};
  logger.warn(message, sanitized);
}

export function logError(message: string, error?: Error, metadata?: Record<string, unknown>): void {
  const sanitized = metadata ? sanitizeForLogging(metadata) : {};

  const errorInfo = error ? {
    errorType: error.name,
    errorMessage: error.message,
  } : {};

  logger.error(message, { ...sanitized, ...errorInfo });
}

export function logDebug(message: string, metadata?: Record<string, unknown>): void {
  const sanitized = metadata ? sanitizeForLogging(metadata) : {};
  logger.debug(message, sanitized);
}

export function toUserSafeError(error: Error, genericMessage: string = 'Operation failed'): string {
  logError('Internal error occurred', error);

  return genericMessage;
}

export class UserFacingError extends Error {
  public readonly userMessage: string;

  constructor(userMessage: string, internalMessage?: string) {
    super(internalMessage || userMessage);
    this.name = 'UserFacingError';
    this.userMessage = userMessage;
  }
}

export function withSecureErrorHandling<T extends unknown[], R>(
  fn: (...args: T) => Promise<R>,
  genericErrorMessage: string = 'Operation failed'
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    try {
      return await fn(...args);
    } catch (error) {
      if (error instanceof UserFacingError) {
        throw error;
      }

      logError('Secure operation failed', error as Error);
      throw new UserFacingError(genericErrorMessage);
    }
  };
}

export { logger };

