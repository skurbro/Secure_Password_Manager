import { Request, Response, NextFunction } from 'express';

const isProduction = process.env.NODE_ENV === 'production';

export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
  ];
  res.setHeader('Content-Security-Policy', cspDirectives.join('; '));

  if (isProduction) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  next();
}

export const rateLimitConfig = {
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
};

export const authRateLimitConfig = {
  windowMs: 15 * 60 * 1000,
  max: 20,  // Увеличено для разработки (в продакшене должно быть 5)
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
};

