import { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

const base = { standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests - please slow down' } };

/** Per IP (used before sign-in). */
export function ipLimiter(max: number, minutes: number) {
  return rateLimit({ ...base, windowMs: minutes * 60_000, max });
}

/** Per anonymous user. */
export function userLimiter(max: number, minutes: number) {
  return rateLimit({
    ...base,
    windowMs: minutes * 60_000,
    max,
    keyGenerator: (req: Request, res: Response) => String(res.locals.userId ?? req.ip),
  });
}
