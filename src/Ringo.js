// Ringo.js — AVELYX verification/credit policy engine for the MVP.
// This module keeps verification rules in one place so the Worker, admin tools
// and future school/API connectors can use the same rules.

export const RINGO_DEFAULT_COST = 10;
export const RINGO_ALLOWED_CREDENTIAL_TYPES = [
  'degree',
  'diploma',
  'certificate',
  'transcript',
  'professional certification',
  'training certificate',
  'other'
];
export const RINGO_ALLOWED_MIME = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/webp'
];
export const RINGO_ACTIVE_STATUSES = [
  'submitted',
  'under_review',
  'sent_to_institution',
  'awaiting_institution_response',
  'verified',
  'not_verified',
  'unable_to_verify',
  'rejected'
];
export const RINGO_ACTIVE_REQUEST_STATUSES = [
  'submitted',
  'under_review',
  'sent_to_institution',
  'awaiting_institution_response'
];

const transitions = {
  submitted: new Set(['under_review', 'sent_to_institution', 'rejected']),
  under_review: new Set(['sent_to_institution', 'verified', 'not_verified', 'unable_to_verify', 'rejected']),
  sent_to_institution: new Set(['awaiting_institution_response', 'verified', 'not_verified', 'unable_to_verify', 'rejected']),
  awaiting_institution_response: new Set(['under_review', 'verified', 'not_verified', 'unable_to_verify', 'rejected']),
  verified: new Set([]),
  not_verified: new Set([]),
  unable_to_verify: new Set([]),
  rejected: new Set([])
};

export function normalizeVerificationStatus(value) {
  const s = String(value || '').trim().toLowerCase();
  return RINGO_ACTIVE_STATUSES.includes(s) ? s : 'submitted';
}

export function canVerificationTransition(from, to) {
  const a = normalizeVerificationStatus(from);
  const b = normalizeVerificationStatus(to);
  if (a === b) return true;
  return transitions[a]?.has(b) === true;
}

export function makeVerificationReference() {
  return `VER-${crypto.randomUUID().replaceAll('-', '').slice(0, 12).toUpperCase()}`;
}

export function sanitizeFileName(name) {
  return String(name || 'document').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 180);
}

export function connectorRequest({ institutionId, credentialType, reference }) {
  return {
    engine: 'RINGO',
    institution_id: Number(institutionId),
    credential_type: String(credentialType || '').toLowerCase(),
    reference: String(reference || ''),
    requested_at: new Date().toISOString()
  };
}
