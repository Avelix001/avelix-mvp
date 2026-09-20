# AVELYX Complete MVP

AVELYX is a professional identity, digital CV and controlled credential-verification platform.

## Cloudflare
- Worker name: `avelix-mvp`
- Entry point: `src/index.js`
- Verification engine: `src/Ringo.js`
- Assets: `public/`
- D1 binding: `DB`
- Existing database: `avelix-db`

## Deploy
1. Keep the existing `wrangler.json` values.
2. Replace the repository `src/index.js` with this build's `src/index.js`.
3. Add `src/Ringo.js`.
4. Replace/update the `public/` files from this package.
5. Commit to the existing GitHub repo.
6. Let the existing GitHub → Cloudflare deployment run.
7. Do not rerun the original `schema.sql`.
8. If needed, apply `migration_complete_build.sql` to the existing D1 database one statement at a time.

## Admin
Admin access continues to use the existing `ADMIN_EMAIL` Worker setting.

Admin pages:
- `/admin.html`
- `/admin-institutions.html`

## Verification
Paid credential verification is accepted only for institutions whose status is `active`. The system supports manual partner verification now and a connector/API architecture through `Ringo.js` for later institution integrations.

## MVP storage note
Verification documents and profile photos use D1 base64 storage for this MVP. Move these files to Cloudflare R2 before significant scale.

## Build 12 patch notes
- Preserves the existing landing page, crowned AVELYX verification emblem, profile, account-type flows and card artwork.
- Replaces generic advertisement placeholders with cropped AVELYX adverts that do not contain app-store/download messaging.
- Dashboard uses the compact “Stay Ahead With AVELYX” advert; other authenticated pages use the compact verified-card advert.
- Dashboard no longer depends on a `wallets` table to load member identity/balance. AVX balance is read from `profiles.avx_balance`, matching the existing MVP schema.
- Credential verification debits/refunds `profiles.avx_balance` instead of requiring a separate `wallets` table.
- Removes the duplicate admin credential INSERT that could break credential issuance.
- Adds `/admin-login.html` and `/api/admin/check` for clearer admin entry/testing.
- Admin authorization still requires the Cloudflare Worker variable `ADMIN_EMAIL` to exactly match the administrator's AVELYX login email. Do not put the admin password in source code.
- Wallet now shows the live AVX balance, activity history and active package cards. Member-to-member sending/trading/cash-out remain disabled.

## Cloudflare variable required for admin
In Cloudflare Worker settings, add:
`ADMIN_EMAIL` = the exact email used by the administrator's AVELYX account.
Then log in at `/admin-login.html` and enter the same AVELYX email/password.

## Build 14 additions
- 1 AVX = NGN 100 for AVX package configuration.
- Credential-specific verification pricing is admin-controlled.
- Verification payment approval captures AVX into the admin wallet.
- Admin agent and future card approval controls are included.
