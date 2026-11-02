import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { ipLimiter } from '../middleware/limits';
import { User } from '../models/User';

export const authRouter = Router();

/** Creates an anonymous account for a new app install. Nothing personal is stored. */
authRouter.post('/register', ipLimiter(20, 60), async (_req, res, next) => {
  try {
    const user = await User.create({});
    const token = jwt.sign({ sub: String(user._id) }, config.jwtSecret, { expiresIn: '365d' });
    res.json({ token, userId: String(user._id) });
  } catch (e) {
    next(e);
  }
});
