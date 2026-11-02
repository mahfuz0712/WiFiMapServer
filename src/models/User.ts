import { Schema, model } from 'mongoose';

/** Anonymous device account: just a random id. No name, phone, e-mail or location. */
const UserSchema = new Schema(
  {
    banned: { type: Boolean, default: false },
    lastSeenAt: { type: Date, default: Date.now },
    shareDay: { type: String, default: '' },
    shareCount: { type: Number, default: 0 },
  },
  { timestamps: true }
);

export const User = model('User', UserSchema);
