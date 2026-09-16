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
