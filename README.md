# AVELYX Digital CV API Fix

This is a **patch only** for the existing AVELYX Build 14 deployment. It is not a full rebuild.

## File to replace
Replace only:

`src/index.js`

with the `src/index.js` in this package.

## What this patch adds
- `/digital-cv.html` standalone Digital CV page
- `GET /api/digital-cv`
- `PUT /api/digital-cv` for Digital CV-only fields
- automatic creation/check of `digital_cv_data`
- profile data automatically feeds the Digital CV
- verified credentials appear in the Digital CV
- `/v/AVELYX-ID` now renders the Digital CV
- Secure QR `/s/...` now opens the Digital CV
- Digital CV tile added to the dashboard
- Digital CV added to the application menu

## Deployment
From the existing project root:

`npx wrangler deploy`

Do not replace the whole project. Do not delete D1 data. Do not rerun unrelated migrations.
