import 'dotenv/config';

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing environment variable ${name}`);
  return v;
}

function num(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : def;
}

const dataKey = need('DATA_KEY');
if (Buffer.from(dataKey, 'base64').length !== 32) {
  throw new Error('DATA_KEY must be base64 of exactly 32 bytes');
}

export const config = {
  port: num('PORT', 8080),
  mongoUri: need('MONGODB_URI'),
  jwtSecret: need('JWT_SECRET'),
  dataKey,
  pwPepper: need('PW_PEPPER'),
  maxSharesPerDay: num('MAX_SHARES_PER_DAY', 30),
  ownerReportsToHide: num('OWNER_REPORTS_TO_HIDE', 2),
  otherReportsToHide: num('OTHER_REPORTS_TO_HIDE', 3),
};
