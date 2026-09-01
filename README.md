# AVELIX Cloudflare MVP
Cloudflare Workers + D1 prototype. Create an AVX ID, save a public profile, and expose `/v/AVX-XXXXXX`.

1. Create a D1 database called `avelix-db`.
2. Replace `REPLACE_WITH_D1_DATABASE_ID` in `wrangler.json` with its ID.
3. Run `schema.sql` against the D1 database.
4. Push all files to GitHub.
5. Deploy with `npx wrangler deploy`.

The QR image is generated through an external QR image endpoint for this presentation MVP. For production, generate it inside your own Worker and add authentication, privacy, consent, rate limits and a formal verification process.
