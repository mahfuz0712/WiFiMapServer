# WiFiMap Server

Community database for the **Wi-Fi Map** Android app. Node.js + Express + TypeScript + MongoDB (Mongoose).

People share Wi-Fi passwords **on purpose** (public places, cafes, QR codes on the wall, staff-announced Wi-Fi).
It is not a cracking tool: the server only stores what a person typed or scanned and chose to share.

## How the data works
- Key = **BSSID** (the access point's MAC address) + password. `Credential` = one password variant of one BSSID.
- `sharers` = anonymous user ids who shared the same password, `up` / `down` = "worked" / "failed" votes.
- Match levels: `exact` (same BSSID) and `device` (same SSID + first 5 MAC bytes = same router, other band / SSID slot).
- Passwords are **AES-256-GCM encrypted** (`DATA_KEY`) and matched with an HMAC (`PW_PEPPER`). Users are anonymous random ids (JWT, 1 year).

## Safety / abuse rules built in
- Personal phone hotspots (`kind = HOTSPOT`) and open / enterprise networks are rejected.
- The app sends `confirm: true` (user ticked "this password is public or I have permission").
- 1 active share per person per access point, daily share limit, per-user + per-IP rate limits, 50 KB body limit.
- Voting: you cannot vote on your own share. Many "failed" votes hide a password automatically.
- Reports: `owner` (default 2 different people) or `private` / `abuse` (default 3) hide a password for good.
- No name, phone, e-mail or location is ever stored.

## Run locally
```bash
npm install
cp .env.example .env        # fill MONGODB_URI + 3 secrets (commands are inside the file)
npm run dev                 # http://localhost:8080/health
```

## Deploy on Render (free)
1. Create a free MongoDB Atlas cluster, add a user, allow `0.0.0.0/0`, copy the connection string.
2. Push this folder to its own GitHub repo.
3. Render > **New + > Blueprint** > pick the repo (uses `render.yaml`). Paste `MONGODB_URI` when asked;
   `JWT_SECRET`, `DATA_KEY`, `PW_PEPPER` are generated automatically.
4. Open `https://<your-service>.onrender.com/health`. In the app: **SYS > COMMUNITY DATABASE > SERVER ADDRESS**
   (or change `API_BASE` in `AppInfo.kt`) and press TEST CONNECTION.
   The free plan sleeps after 15 min - the first request can take about a minute.

> Never change `DATA_KEY` after real data exists - stored passwords could no longer be decrypted.

## API (`/api/v1`, JSON, `Authorization: Bearer <token>` except register / stats)
| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | anonymous account -> `{ token, userId }` |
| GET | `/stats` | `{ networks, shares, users }` |
| POST | `/wifi/lookup` | `{ networks:[{bssid,ssid}] }` -> counts only, no passwords |
| POST | `/wifi/network` | `{ bssid, ssid }` -> list of shared passwords |
| POST | `/wifi/share` | share a password (needs `confirm: true`) |
| POST | `/wifi/credentials/:id/vote` | `{ value: 1 | 0 | -1 }` |
| POST | `/wifi/credentials/:id/report` | `{ reason: wrong | private | owner | abuse }` |
| GET | `/wifi/mine` | passwords I shared |
| DELETE | `/wifi/credentials/:id/mine` | remove my share |
