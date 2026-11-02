import { Schema, model } from 'mongoose';

export interface CredentialDoc {
  _id: any;
  bssid: string;
  bssidPrefix: string;
  ssid: string;
  pwHash: string;
  pwEnc: string;
  security: string;
  kind: string;
  band?: string;
  channel?: number;
  brand?: string;
  via: 'manual' | 'qr';
  sharers: string[];
  up: string[];
  down: string[];
  reports: { user: string; reason: string; at: Date }[];
  hidden: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/** One password variant for one access point (BSSID), with everybody who shared / voted on it. */
const CredentialSchema = new Schema<CredentialDoc>(
  {
    bssid: { type: String, required: true, index: true },
    bssidPrefix: { type: String, required: true, index: true }, // first 5 octets: same router, other band / SSID slot
    ssid: { type: String, required: true },
    pwHash: { type: String, required: true },
    pwEnc: { type: String, required: true },
    security: { type: String, required: true },
    kind: { type: String, default: 'ROUTER' },
    band: String,
    channel: Number,
    brand: String,
    via: { type: String, enum: ['manual', 'qr'], default: 'manual' },
    sharers: { type: [String], default: [], index: true },
    up: { type: [String], default: [] },
    down: { type: [String], default: [] },
    reports: { type: [{ user: String, reason: String, at: { type: Date, default: Date.now } }], default: [] },
    hidden: { type: Boolean, default: false },
  },
  { timestamps: true }
);

CredentialSchema.index({ bssid: 1, pwHash: 1 }, { unique: true });

export const Credential = model<CredentialDoc>('Credential', CredentialSchema);
