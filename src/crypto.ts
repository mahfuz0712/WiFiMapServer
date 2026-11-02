import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto';
import { config } from './config';

const key = Buffer.from(config.dataKey, 'base64');

/** AES-256-GCM. Output: iv.tag.ciphertext (base64 parts). */
export function encrypt(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
}

export function decrypt(blob: string): string {
  const [iv, tag, enc] = blob.split('.').map((p) => Buffer.from(p, 'base64'));
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

/** Same password -> same hash, so two people sharing it are counted together. */
export function passwordHash(password: string): string {
  return createHmac('sha256', config.pwPepper).update(password).digest('hex');
}
