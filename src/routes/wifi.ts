import { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import { isValidObjectId } from 'mongoose';
import { z } from 'zod';
import { config } from '../config';
import { decrypt, encrypt, passwordHash } from '../crypto';
import { requireAuth } from '../middleware/auth';
import { userLimiter } from '../middleware/limits';
import { Credential, CredentialDoc } from '../models/Credential';
import { User } from '../models/User';

export const wifiRouter = Router();
wifiRouter.use(requireAuth);

// ------------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------------

const ah =
  (fn: (req: Request, res: Response) => Promise<unknown>): RequestHandler =>
  (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };

const BSSID_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const prefixOf = (b: string) => b.split(':').slice(0, 5).join(':');
const uid = (res: Response) => String(res.locals.userId);

const bssid = z
  .string()
  .transform((s) => s.trim().toLowerCase().replace(/-/g, ':'))
  .refine((v) => BSSID_RE.test(v), 'invalid BSSID');
const ssid = z.string().min(1).max(64);
const netSchema = z.object({ bssid, ssid });

/** A password with many "failed" votes and few "worked" votes disappears by itself. */
function visible(c: Pick<CredentialDoc, 'hidden' | 'up' | 'down'>): boolean {
  if (c.hidden) return false;
  return !(c.down.length >= 3 && c.down.length > c.up.length * 2);
}

interface Item {
  id: string;
  password: string;
  sharers: number;
  up: number;
  down: number;
  updatedAt: number;
  match: 'exact' | 'device';
  myVote: number;
  mine: boolean;
  via: string;
}

function toItem(c: CredentialDoc, userId: string, match: 'exact' | 'device'): Item {
  return {
    id: String(c._id),
    password: decrypt(c.pwEnc),
    sharers: c.sharers.length,
    up: c.up.length,
    down: c.down.length,
    updatedAt: new Date(c.updatedAt).getTime(),
    match,
    myVote: c.up.includes(userId) ? 1 : c.down.includes(userId) ? -1 : 0,
    mine: c.sharers.includes(userId),
    via: c.via,
  };
}

/** Everything known for one access point: exact BSSID first, then the same router's other radios / SSID slots. */
async function collect(b: string, s: string, userId: string): Promise<Item[]> {
  const docs = await Credential.find({
    hidden: false,
    $or: [{ bssid: b }, { bssidPrefix: prefixOf(b), ssid: s }],
  })
    .limit(80)
    .lean<CredentialDoc[]>();

  const byPassword = new Map<string, Item>();
  for (const d of docs) {
    if (!visible(d)) continue;
    const it = toItem(d, userId, d.bssid === b ? 'exact' : 'device');
    const old = byPassword.get(it.password);
    if (!old) {
      byPassword.set(it.password, it);
    } else {
      // same password seen on the exact BSSID and on a sibling radio: merge, keep the exact id for voting
      const exact = it.match === 'exact' ? it : old;
      byPassword.set(it.password, {
        ...exact,
        sharers: old.sharers + it.sharers,
        up: old.up + it.up,
        down: old.down + it.down,
        updatedAt: Math.max(old.updatedAt, it.updatedAt),
        mine: old.mine || it.mine,
        match: old.match === 'exact' || it.match === 'exact' ? 'exact' : 'device',
      });
    }
  }
  return [...byPassword.values()]
    .sort((a, b2) => b2.up - b2.down - (a.up - a.down) || b2.sharers - a.sharers)
    .slice(0, 10);
}

// ------------------------------------------------------------------------------------------------
// POST /wifi/lookup   -> which of these access points have shared passwords? (no passwords returned)
// ------------------------------------------------------------------------------------------------

const lookupSchema = z.object({ networks: z.array(netSchema).min(1).max(60) });

wifiRouter.post(
  '/lookup',
  userLimiter(400, 60),
  ah(async (req, res) => {
    const { networks } = lookupSchema.parse(req.body);
    const bssids = [...new Set(networks.map((n) => n.bssid))];
    const prefixes = [...new Set(networks.map((n) => prefixOf(n.bssid)))];
    const docs = await Credential.find({
      hidden: false,
      $or: [{ bssid: { $in: bssids } }, { bssidPrefix: { $in: prefixes } }],
    })
      .select('bssid bssidPrefix ssid sharers up down hidden')
      .limit(3000)
      .lean<CredentialDoc[]>();

    const results: Record<string, { match: string; variants: number; sharers: number }> = {};
    for (const n of networks) {
      const exact = docs.filter((d) => d.bssid === n.bssid && visible(d));
      const use =
        exact.length > 0
          ? { list: exact, match: 'exact' }
          : { list: docs.filter((d) => d.bssidPrefix === prefixOf(n.bssid) && d.ssid === n.ssid && visible(d)), match: 'device' };
      if (use.list.length > 0) {
        results[n.bssid] = {
          match: use.match,
          variants: use.list.length,
          sharers: new Set(use.list.flatMap((d) => d.sharers)).size,
        };
      }
    }
    res.json({ results });
  })
);

// ------------------------------------------------------------------------------------------------
// POST /wifi/network  -> the passwords for one access point
// ------------------------------------------------------------------------------------------------

wifiRouter.post(
  '/network',
  userLimiter(200, 60),
  ah(async (req, res) => {
    const n = netSchema.parse(req.body);
    res.json({ credentials: await collect(n.bssid, n.ssid, uid(res)) });
  })
);

// ------------------------------------------------------------------------------------------------
// POST /wifi/share
// ------------------------------------------------------------------------------------------------

const shareSchema = netSchema.extend({
  password: z
    .string()
    .min(5)
    .max(64)
    // eslint-disable-next-line no-control-regex
    .refine((p) => !/[\u0000-\u001f\u007f]/.test(p), 'password has invalid characters'),
  security: z.enum(['WEP', 'WPA', 'WPA2', 'WPA3', 'WPA/WPA2', 'WPA2/WPA3']),
  kind: z.enum(['ROUTER', 'HOTSPOT']).default('ROUTER'),
  band: z.string().max(5).optional(),
  channel: z.number().int().min(0).max(300).optional(),
  brand: z.string().max(40).optional(),
  via: z.enum(['manual', 'qr']).default('manual'),
  confirm: z.literal(true),
});

wifiRouter.post(
  '/share',
  userLimiter(40, 60),
  ah(async (req, res) => {
    const d = shareSchema.parse(req.body);
    const userId = uid(res);

    if (d.kind === 'HOTSPOT') {
      return res.status(403).json({ error: 'Personal phone hotspots cannot be shared' });
    }
    if (d.security !== 'WEP' && d.password.length < 8) {
      return res.status(400).json({ error: 'A Wi-Fi password needs at least 8 characters' });
    }

    const user = await User.findById(userId);
    if (!user || user.banned) return res.status(403).json({ error: 'This device is not allowed to share' });
    const day = new Date().toISOString().slice(0, 10);
    if (user.shareDay !== day) {
      user.shareDay = day;
      user.shareCount = 0;
    }
    if (user.shareCount >= config.maxSharesPerDay) {
      return res.status(429).json({ error: 'Daily share limit reached - thank you, try again tomorrow' });
    }

    const hash = passwordHash(d.password);

    // one active share per person per access point: sharing a new password replaces the old one
    const mineBefore = await Credential.find({ bssid: d.bssid, sharers: userId, pwHash: { $ne: hash } });
    for (const old of mineBefore) {
      old.sharers = old.sharers.filter((x) => x !== userId);
      if (old.sharers.length === 0) await old.deleteOne();
      else await old.save();
    }

    let doc = await Credential.findOne({ bssid: d.bssid, pwHash: hash });
    if (!doc) {
      doc = await Credential.create({
        bssid: d.bssid,
        bssidPrefix: prefixOf(d.bssid),
        ssid: d.ssid,
        pwHash: hash,
        pwEnc: encrypt(d.password),
        security: d.security,
        kind: d.kind,
        band: d.band,
        channel: d.channel,
        brand: d.brand,
        via: d.via,
        sharers: [userId],
      });
    } else {
      if (doc.hidden) {
        return res.status(409).json({ error: 'This password was removed after reports and cannot be added again' });
      }
      if (!doc.sharers.includes(userId)) {
        doc.sharers.push(userId);
        doc.up = doc.up.filter((x) => x !== userId);
        doc.down = doc.down.filter((x) => x !== userId);
        await doc.save();
      }
    }

    user.shareCount += 1;
    await user.save();
    res.json({ credentials: await collect(d.bssid, d.ssid, userId) });
  })
);

// ------------------------------------------------------------------------------------------------
// votes + reports
// ------------------------------------------------------------------------------------------------

const voteSchema = z.object({ value: z.union([z.literal(-1), z.literal(0), z.literal(1)]) });

wifiRouter.post(
  '/credentials/:id/vote',
  userLimiter(300, 60),
  ah(async (req, res) => {
    const id = String(req.params.id);
    if (!isValidObjectId(id)) return res.status(404).json({ error: 'Not found' });
    const { value } = voteSchema.parse(req.body);
    const userId = uid(res);
    const doc = await Credential.findById(id);
    if (!doc || doc.hidden) return res.status(404).json({ error: 'Not found' });
    if (doc.sharers.includes(userId)) {
      return res.status(403).json({ error: 'You cannot vote on a password you shared' });
    }
    doc.up = doc.up.filter((x) => x !== userId);
    doc.down = doc.down.filter((x) => x !== userId);
    if (value === 1) doc.up.push(userId);
    if (value === -1) doc.down.push(userId);
    await doc.save();
    res.json({ ok: true, up: doc.up.length, down: doc.down.length });
  })
);

const reportSchema = z.object({ reason: z.enum(['wrong', 'private', 'owner', 'abuse']) });

wifiRouter.post(
  '/credentials/:id/report',
  userLimiter(60, 60),
  ah(async (req, res) => {
    const id = String(req.params.id);
    if (!isValidObjectId(id)) return res.status(404).json({ error: 'Not found' });
    const { reason } = reportSchema.parse(req.body);
    const userId = uid(res);
    const doc = await Credential.findById(id);
    if (!doc) return res.status(404).json({ error: 'Not found' });

    if (!doc.reports.some((r) => r.user === userId)) {
      doc.reports.push({ user: userId, reason, at: new Date() });
    }
    if (reason === 'wrong' && !doc.sharers.includes(userId)) {
      doc.up = doc.up.filter((x) => x !== userId);
      if (!doc.down.includes(userId)) doc.down.push(userId);
    }
    const owner = new Set(doc.reports.filter((r) => r.reason === 'owner').map((r) => r.user)).size;
    const other = new Set(doc.reports.filter((r) => r.reason === 'private' || r.reason === 'abuse').map((r) => r.user)).size;
    if (owner >= config.ownerReportsToHide || other >= config.otherReportsToHide) doc.hidden = true;
    await doc.save();
    res.json({ ok: true, hidden: doc.hidden });
  })
);

// ------------------------------------------------------------------------------------------------
// my shares
// ------------------------------------------------------------------------------------------------

wifiRouter.get(
  '/mine',
  userLimiter(120, 60),
  ah(async (_req, res) => {
    const userId = uid(res);
    const docs = await Credential.find({ sharers: userId }).sort({ createdAt: -1 }).limit(200).lean<CredentialDoc[]>();
    res.json({
      items: docs.map((c) => ({
        id: String(c._id),
        ssid: c.ssid,
        bssid: c.bssid,
        password: decrypt(c.pwEnc),
        sharers: c.sharers.length,
        up: c.up.length,
        down: c.down.length,
        createdAt: new Date(c.createdAt).getTime(),
      })),
    });
  })
);

wifiRouter.delete(
  '/credentials/:id/mine',
  userLimiter(120, 60),
  ah(async (req, res) => {
    const id = String(req.params.id);
    if (!isValidObjectId(id)) return res.status(404).json({ error: 'Not found' });
    const userId = uid(res);
    const doc = await Credential.findById(id);
    if (!doc || !doc.sharers.includes(userId)) return res.status(404).json({ error: 'Not found' });
    doc.sharers = doc.sharers.filter((x) => x !== userId);
    if (doc.sharers.length === 0) await doc.deleteOne();
    else await doc.save();
    res.json({ ok: true });
  })
);
