import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';

/** Reads the anonymous device token. The user id ends up in res.locals.userId. */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not signed in' });
  }
  try {
    const p = jwt.verify(h.slice(7), config.jwtSecret) as { sub?: string };
    if (!p.sub) throw new Error('no subject');
    res.locals.userId = p.sub;
    next();
  } catch {
    res.status(401).json({ error: 'Session expired' });
  }
}
