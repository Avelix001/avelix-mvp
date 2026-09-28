# AVELYX Build 15 — Final UI + Digital CV + Access Control

## Base
This build is based on **AVELYX Build 14 — AVX + Admin + Pricing**. The existing D1 binding and backend feature set are preserved.

## What changed
- Rebuilt the public landing page to match the approved AVELYX design direction.
- Preserved the Build 14 login API and repaired/organized the login page UI.
- Restored working registration and email verification pages/routes.
- Added working 2FA challenge handoff for accounts that have 2FA enabled.
- Rebuilt the member dashboard with the AVELYX crowned-A verification emblem and a clean sidebar/topbar layout.
- Added standalone `/digital-cv.html`.
- Digital CV reads existing profile data automatically.
- Digital CV reads verified credentials from the existing credentials table.
- Existing `digital_cv_data` table is used for optional CV-only fields such as soft skills, awards, NYSC, work experience and summary.
- Added public Digital CV route `/v/AVX-ID`.
- Secure QR `/s/TOKEN` now opens the Digital CV public view rather than the old basic profile card.
- QR generation still revokes older active QR tokens and keeps the one-scan/expiry behavior from Build 14.
- Added approved-access viewer `/access.html?request_id=ID`.
- Approved protected information is available for exactly 3 days from approval.
- Permission page now shows incoming requests and outgoing requests.
- Approved outgoing requests provide a direct **View Approved Information** button.
- Notifications now surface pending permission requests and approvals.
- Individual, Entrepreneur and Business profiles are visually distinguished in the Digital CV.
- Business records are explicitly described as issuer/source-dependent; AVELYX does not label user-entered claims as issuer-verified automatically.
- Existing AVX wallet, verification center, admin controls, card orders, jobs/opportunities and credential administration are retained.

## Existing D1 table
The current AVELYX project already has `digital_cv_data` in D1. **Do not delete or recreate the table.** The Worker also calls `ensureDigitalCVTable()` safely at runtime.

## Deployment
From the project root:

```bash
npx wrangler deploy
```

Do not paste a filename into the D1 SQL console. The SQL files in the repository are documentation/migration support; uploading them to GitHub does not execute them.

## Important current flow

### Login
`/login.html` → `POST /api/login` → session cookie → `/dashboard.html`

### Registration
`/register.html` → `POST /api/register` → account/profile created → dashboard

### Digital CV
`Profile fields + credentials + digital_cv_data` → `/digital-cv.html`

### QR
`Dashboard → Secure QR → POST /api/share → /s/TOKEN → public Digital CV`

### Protected information
`Requester → /permissions.html → request → owner approves selected fields → 3-day access → /access.html?request_id=ID → automatic expiry`

### Public information
Public QR/Digital CV keeps phone/email protected/masked unless the separate permission system grants access.
