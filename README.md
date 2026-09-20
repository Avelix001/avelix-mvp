# AVELYX — Old Working Login Base + Digital CV API Fix

This patch intentionally uses the previously working `avelyx-fixed-index.js` as the base and adds ONLY the Digital CV functionality.

## Files
- `src/index.js` — replacement Worker entry file
- `README.md`

## What was preserved
- Existing working login page and `/api/login`
- Registration and email verification
- Dashboard
- Profile
- QR generation and existing share-token behavior
- Permissions, notifications, wallet, opportunities
- Existing admin/credential functions in the base file

## Digital CV additions
- `/digital-cv.html`
- `GET /api/digital-cv`
- `PUT /api/digital-cv`
- `digital_cv_data` table check/creation
- Existing profile information automatically appears in the Digital CV
- Verified credentials automatically appear in the Digital CV
- CV-only sections: summary, hard skills, soft skills, education, NYSC, awards, work experience, professional certifications
- `/v/AVELYX-ID` displays the Digital CV
- Secure QR `/s/...` displays the Digital CV
- Dashboard has a Digital CV tile

## Deployment
1. Replace only your repository `src/index.js` with the `src/index.js` in this ZIP.
2. Keep the existing D1 database and all existing data.
3. Commit/push to GitHub.
4. Deploy the Worker normally with `npx wrangler deploy`.

## SQL
No SQL Console action is required if `digital_cv_data` already exists. The Worker also runs `CREATE TABLE IF NOT EXISTS` as a safety check.

## Testing
After deployment:
1. Open `/login.html` and confirm the login screen appears.
2. Log in.
3. Open `/dashboard.html`.
4. Open `/digital-cv.html`.
5. Open `/api/digital-cv` while logged in.
6. Edit Profile and confirm the changed profile fields appear in the Digital CV.
7. Generate a QR and scan it. It should open the Digital CV.
8. Open `/v/YOUR-AVELYX-ID` and confirm the public Digital CV appears.
