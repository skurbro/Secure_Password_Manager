import express, { Express, Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import path from 'path';

import { authRouter } from './routes/auth';
import { vaultRouter } from './routes/vault';
import { csrfProtection, csrfErrorHandler, addCsrfTokenToResponse, createSignedCsrfToken } from './middleware/csrf';
import { securityHeaders } from './middleware/security';
import { rateLimitConfig, authRateLimitConfig } from './middleware/security';
import { logInfo, logError } from '../core/logger';
import { vaultStorage } from '../core/storage';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    derivedKey?: string;
    isAuthenticated?: boolean;
    createdAt?: number;
  }
}

const app: Express = express();
// Rate limiting middleware
const globalLimiter = rateLimit(rateLimitConfig);
const authLimiter = rateLimit(authRateLimitConfig);
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) app.set('trust proxy', 1);

app.use(securityHeaders);
app.use(globalLimiter);

const allowedOrigins = [process.env.FRONTEND_URL || '', 'http://localhost:3000', 'http://localhost:8080'].filter(Boolean);
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    if (process.env.DEBUG_CSRF === '1') console.log(`[CORS DEBUG] origin=${origin} not allowed`);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
  exposedHeaders: ['X-CSRF-Token'],
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TIMEOUT = 60 * 60 * 1000;
const useSecureCookie = process.env.SECURE_COOKIE === 'true' || (isProduction && process.env.FRONTEND_URL?.startsWith('https://'));
app.use(session({
  name: 'spm_session',
  secret: sessionSecret,
  resave: true,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    secure: useSecureCookie,
    sameSite: isProduction ? ('strict' as const) : ('lax' as const),
    path: '/',
    maxAge: SESSION_TIMEOUT,
  },
}));

app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logInfo(`${req.method} ${req.path}`, { statusCode: res.statusCode, duration: `${duration}ms`, ip: req.ip });
  });
  next();
});

app.get('/health', (req: Request, res: Response) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/api/health', (req: Request, res: Response) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.use(addCsrfTokenToResponse);

app.get('/api/csrf-token', (req: Request, res: Response) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  const signed = createSignedCsrfToken();
  req.session.csrfToken = signed;
  req.session.save((err) => {
    if (process.env.DEBUG_CSRF === '1') console.log('[CSRF DEBUG] /api/csrf-token saved', err);
    res.json({ csrfToken: signed });
  });
});

// Temporary debug endpoint to inspect session and headers when debugging CSRF
app.get('/api/debug-session', (req: Request, res: Response) => {
  if (process.env.DEBUG_CSRF !== '1') { res.status(404).end(); return; }
  return res.json({
    sessionID: req.sessionID,
    sessionTokenPresent: !!req.session?.csrfToken,
    sessionToken: req.session?.csrfToken ? `${req.session.csrfToken.slice(0,8)}...` : null,
    headers: {
      origin: req.headers.origin || null,
      cookie: req.headers.cookie || null,
      x_csrf_token: req.headers['x-csrf-token'] || req.headers['X-CSRF-Token'] || null,
    },
  });
});

app.use('/api/auth', authRouter);
app.use('/api/auth', authLimiter);
app.use('/api/vault', csrfProtection);
app.use('/api/vault', vaultRouter);

if (isProduction) {
  const frontendPath = path.join(__dirname, '../public');
  app.use(express.static(frontendPath));
  app.get('*', (req: Request, res: Response) => res.sendFile(path.join(frontendPath, 'index.html')));
}

app.use(csrfErrorHandler);
app.use((req: Request, res: Response) => res.status(404).json({ error: 'Not found' }));

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logError('Unhandled error', err, { path: req.path, method: req.method, ip: req.ip });
  res.status(500).json({ error: 'Internal server error', message: 'An unexpected error occurred. Please try again.' });
});

async function startServer(): Promise<void> {
  try {
    await vaultStorage.initialize();
    logInfo('Database initialized');
    app.listen(PORT, '0.0.0.0', () => {
      logInfo('Server started', { port: PORT, environment: isProduction ? 'production' : 'development', corsOrigin: corsOptions.origin });
      console.log(`Server running on: http://localhost:${PORT} (${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'})`);
    });
  } catch (error) {
    logError('Failed to start server', error as Error);
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

process.on('SIGINT', () => { logInfo('Server shutting down...'); vaultStorage.close(); process.exit(0); });

process.on('SIGTERM', () => {
  logInfo('Server shutting down...');
  vaultStorage.close();
  process.exit(0);
});

startServer();

export { app };

