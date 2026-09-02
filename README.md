# AVELIX Cloudflare MVP — Member System

## Included
- AVELIX registration + unique AVX ID
- Secure login/session cookies
- Member dashboard
- Profile editing
- One-scan temporary QR sharing
- Public AVELIX profile URLs
- Coming Soon cards for Verified Credentials, Basic Card and Platinum Card
- Cloudflare Workers + D1 + Static Assets architecture

## Database
Run `schema.sql` against the existing AVELIX D1 database before deploying the updated Worker.

Example with Wrangler:
`npx wrangler d1 execute avelix-db --remote --file=./schema.sql`

## Deploy
`npx wrangler deploy`

The secure QR uses a random token and stores only its SHA-256 hash in D1. The QR itself does not contain profile information. It is limited to one successful scan and expires after 30 minutes.
