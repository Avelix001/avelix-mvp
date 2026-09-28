# AVELYX Build 14 — AVX pricing and admin controls

This build is based on the working Build 13 package.

## Included
- Medium five-slide advertisement carousel retained across member pages and landing page.
- Dashboard server-renders member identity and AVX balance to avoid a permanent Loading state.
- `1 AVX = ₦100` is enforced for AVX packages created/edited in Admin.
- Credential-specific AVX prices are stored in `credential_pricing` and editable from Admin without rebuilding.
- Verification submissions use the selected credential's configured price.
- Verification payment is `pending_payment` first; admin approval then debits the member AVX balance and credits the AVELYX admin wallet.
- Admin can reject a pending verification payment without charging the member.
- Admin wallet adjustment supports positive and negative member AVX adjustments; positive issuance respects the treasury, negative adjustments return AVX to the admin wallet.
- Admin can create/edit/delete/activate agents.
- Admin can review future card orders and approve/reject them. Cards remain disabled until the `cards_enabled` feature is launched.
- New admin platform payload includes pricing, payment queue, admin wallet, agents and card orders.
- New crowned AVELYX emblem remains unchanged.

## Pricing behavior
No credential price is assumed. If a credential type has no active price, member submission is blocked with a clear message. This allows prices to be entered later from Admin without another code rebuild.

## Payment behavior
The current MVP does not claim an automated bank/payment-gateway confirmation. A payment request can be marked pending and approved by an authorized admin. Approval performs the AVX debit and admin-wallet credit atomically as the platform-side service-credit capture.

## Database
The Worker contains an `ensureAdminControlTables()` safety initializer. The migration file is included for explicit D1 setup, but the original schema should not be rerun.
