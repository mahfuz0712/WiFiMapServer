import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { ZodError } from 'zod';
import { config } from './config';
import { ipLimiter } from './middleware/limits';
import { Credential } from './models/Credential';
import { User } from './models/User';
import { authRouter } from './routes/auth';
import { wifiRouter } from './routes/wifi';

const app = express();
app.set('trust proxy', 1); // Render / most hosts sit behind a proxy
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50kb' }));
app.use(ipLimiter(1200, 15));

app.get('/', (_req, res) => {
  res.json({ name: 'wifimap-server', ok: true });
});
app.get('/health', (_req, res) => {
  res.json({ ok: true, db: mongoose.connection.readyState === 1 });
});

const api = express.Router();
api.get('/stats', async (_req, res, next) => {
  try {
    const [networks, shares, users] = await Promise.all([
      Credential.distinct('bssid', { hidden: false }).then((a) => a.length),
      Credential.countDocuments({ hidden: false }),
      User.estimatedDocumentCount(),
    ]);
    res.json({ networks, shares, users });
  } catch (e) {
    next(e);
  }
});
api.use('/auth', authRouter);
api.use('/wifi', wifiRouter);
app.use('/api/v1', api);

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ZodError) {
    const i = err.issues[0];
    return res.status(400).json({ error: `Invalid request${i ? `: ${i.path.join('.')} ${i.message}` : ''}` });
  }
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

async function main() {
  await mongoose.connect(config.mongoUri);
  console.log('MongoDB connected');
  await Credential.syncIndexes();
  app.listen(config.port, () => console.log(`wifimap-server listening on ${config.port}`));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
