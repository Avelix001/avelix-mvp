const SESSION_COOKIE = '__Host-avelix_session';
const SESSION_DAYS = 7;
const QR_MINUTES = 30;
const QR_MAX_USES = 100;
const REFERRAL_PREFIX = 'AVELIX';
const VERIFY_MINUTES = 15;
const VERIFY_RESEND_SECONDS = 60;
const LOGIN_CHALLENGE_MINUTES = 10;
const MFA_RECOVERY_COUNT = 8;

const esc = (v = '') => String(v).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=UTF-8', 'cache-control': 'no-store' }});
const now = () => Math.floor(Date.now() / 1000);
const makeId = () => `AVX-${crypto.randomUUID().replaceAll('-', '').slice(0, 10).toUpperCase()}`;
const randomToken = () => crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');

const randomDigits = (n = 6) => {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(bytes, b => String(b % 10)).join('');
};
function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, value = 0, out = '';
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, value = 0; const out = [];
  for (const ch of input.replace(/=+$/,'').toUpperCase()) { const v = alphabet.indexOf(ch); if (v < 0) continue; value = (value << 5) | v; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function hmacSha1(keyBytes, counter) {
  const data = new ArrayBuffer(8); const view = new DataView(data); view.setUint32(0, Math.floor(counter / 0x100000000)); view.setUint32(4, counter >>> 0);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name:'HMAC', hash:'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}
async function totpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30); const mac = await hmacSha1(base32Decode(secret), counter); const offset = mac[mac.length - 1] & 15;
  const num = ((mac[offset] & 127) << 24) | (mac[offset+1] << 16) | (mac[offset+2] << 8) | mac[offset+3]; return String(num % 1000000).padStart(6,'0');
}
async function verifyTotp(secret, code) { const c = String(code || '').replace(/\D/g,''); if (c.length !== 6) return false; for (let drift=-1; drift<=1; drift++) if (await totpCode(secret, Date.now()+drift*30000) === c) return true; return false; }
async function sendEmail(env, to, subject, html, text) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) throw new Error('Email service is not configured. Add RESEND_API_KEY and EMAIL_FROM to Worker secrets/variables.');
  const r = await fetch('https://api.resend.com/emails', { method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${env.RESEND_API_KEY}`}, body:JSON.stringify({from:env.EMAIL_FROM,to:[to],subject,html,text}) });
  if (!r.ok) throw new Error(`Email delivery failed (${r.status}).`); return r.json();
}
async function sendVerificationEmail(env, email, name, code) {
  const safeName = esc(name); const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:30px;background:#071025;color:#fff"><div style="font-size:24px;font-weight:900;letter-spacing:4px">AVELIX</div><h1>Verify your email</h1><p>Hello ${safeName}, use this code to verify your AVELIX account:</p><div style="font-size:34px;font-weight:900;letter-spacing:10px;background:#111b3d;padding:18px;text-align:center;border-radius:14px">${code}</div><p>This code expires in ${VERIFY_MINUTES} minutes. If you did not create this account, you can ignore this email.</p></div>`;
  await sendEmail(env,email,'Verify your AVELIX email',html,`Your AVELIX verification code is ${code}. It expires in ${VERIFY_MINUTES} minutes.`);
}
async function hashRecoveryCode(code) { return sha256(code); }

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function passwordHash(password, saltHex = null) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `${bytesToHex(salt)}:${bytesToHex(new Uint8Array(bits))}`;
}
const bytesToHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const hexToBytes = hex => new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));
async function verifyPassword(password, stored) {
  const [salt] = stored.split(':');
  return (await passwordHash(password, salt)) === stored;
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const match = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}
async function currentUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const hash = await sha256(token);
  return env.DB.prepare(`SELECT u.id AS user_id, u.email AS login_email, p.* FROM sessions s JOIN users u ON u.id=s.user_id JOIN profiles p ON p.id=u.profile_id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash, now()).first();
}
async function createSession(userId, env) {
  const token = randomToken();
  await env.DB.prepare('INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)').bind(userId, await sha256(token), now() + SESSION_DAYS * 86400).run();
  return token;
}
function withSession(response, token, maxAge = SESSION_DAYS * 86400) {
  const headers = new Headers(response.headers);
  headers.append('Set-Cookie', cookie(SESSION_COOKIE, token, maxAge));
  return new Response(response.body, { status: response.status, headers });
}

async function register(request, env) {
  const body = await request.json();
  const accountType = ['individual','entrepreneur','business'].includes(body.account_type) ? body.account_type : 'individual';
  const fullName = String(body.full_name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const organization = String(body.organization || '').trim();
  const cacNumber = String(body.cac_number || '').trim();
  const referralCode = String(body.referral_code || '').trim().toUpperCase();
  if (!fullName || !email || password.length < 8) return json({ error: 'Name, email and a password of at least 8 characters are required.' }, 400);
  if (accountType === 'business' && !organization) return json({ error: 'Business accounts require a business name.' }, 400);
  const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (exists) return json({ error: 'An account with this email already exists. Please log in.' }, 409);
  let referrer = null;
  if (referralCode) referrer = await env.DB.prepare('SELECT id, avx_id FROM profiles WHERE referral_code=?').bind(referralCode).first();
  if (referralCode && !referrer) return json({ error: 'That referral link is not valid.' }, 400);

  const avxId = makeId();
  const myReferralCode = `${REFERRAL_PREFIX}-${crypto.randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()}`;
  const hash = await passwordHash(password);
  const profileResult = await env.DB.prepare(`INSERT INTO profiles (avx_id, account_type, full_name, title, organization, industry, location, email, phone, website, bio, status, cac_number, referral_code, referred_by_profile_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`)
    .bind(avxId, accountType, fullName, body.title || '', organization, body.industry || '', body.location || '', email, body.phone || '', body.website || '', body.bio || '', cacNumber, myReferralCode, referrer?.id || null).run();
  const profile = await env.DB.prepare('SELECT id FROM profiles WHERE avx_id=?').bind(avxId).first();
  try {
    await env.DB.prepare('INSERT INTO users (profile_id, email, password_hash) VALUES (?, ?, ?)').bind(profile.id, email, hash).run();
    if (referrer) await env.DB.prepare('UPDATE profiles SET referral_count=referral_count+1 WHERE id=?').bind(referrer.id).run();
  } catch (e) {
    await env.DB.prepare('DELETE FROM profiles WHERE id=?').bind(profile.id).run();
    throw e;
  }
  const user = await env.DB.prepare('SELECT id FROM users WHERE profile_id=?').bind(profile.id).first();
  const code = randomDigits(6); const expiresAt = now() + VERIFY_MINUTES * 60;
  await env.DB.prepare('UPDATE users SET email_verified=0, verification_code_hash=?, verification_expires_at=?, verification_attempts=0, last_verification_sent_at=? WHERE id=?').bind(await sha256(code), expiresAt, now(), user.id).run();
  try { await sendVerificationEmail(env, email, fullName, code); } catch (e) {
    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(user.id).run(); await env.DB.prepare('DELETE FROM profiles WHERE id=?').bind(profile.id).run(); throw e;
  }
  return json({ ok: true, requires_email_verification: true, avx_id: avxId, message: 'Account created. Check your email for the verification code.' }, 201);
}
async function login(request, env) {
  const body = await request.json(); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
  const user = await env.DB.prepare('SELECT id, profile_id, password_hash, email_verified, twofa_enabled FROM users WHERE email=?').bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) return json({ error: 'Invalid email or password.' }, 401);
  if (!user.email_verified) return json({ error: 'Please verify your email before logging in.', needs_verification: true, email }, 403);
  if (user.twofa_enabled) {
    const challenge = randomToken(); await env.DB.prepare('INSERT INTO auth_challenges (user_id, token_hash, expires_at) VALUES (?, ?, ?)').bind(user.id, await sha256(challenge), now()+LOGIN_CHALLENGE_MINUTES*60).run();
    return withPendingSession(json({ ok:true, requires_2fa:true }), challenge, LOGIN_CHALLENGE_MINUTES*60);
  }
  const token = await createSession(user.id, env); return withSession(json({ ok: true }), token);
}

function withPendingSession(response, token, maxAge = LOGIN_CHALLENGE_MINUTES * 60) {
  const headers = new Headers(response.headers); headers.append('Set-Cookie', cookie('__Host-avelix_pending', token, maxAge)); return new Response(response.body,{status:response.status,headers});
}
function getPendingUser(request) { return getCookie(request,'__Host-avelix_pending'); }
async function pendingUser(request, env) {
  const token=getPendingUser(request); if(!token) return null; return env.DB.prepare('SELECT u.id AS user_id, u.twofa_enabled FROM auth_challenges c JOIN users u ON u.id=c.user_id WHERE c.token_hash=? AND c.expires_at>?').bind(await sha256(token),now()).first();
}
async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
  return withSession(json({ ok: true }), '', 0);
}

async function verifyEmail(request, env) {
  const body=await request.json(); const email=String(body.email||'').trim().toLowerCase(); const code=String(body.code||'').trim();
  const user=await env.DB.prepare('SELECT id, profile_id, verification_code_hash, verification_expires_at, verification_attempts, email_verified FROM users WHERE email=?').bind(email).first();
  if(!user) return json({error:'Account not found.'},404); if(user.email_verified) return json({ok:true,message:'Email already verified.'});
  if((user.verification_attempts||0)>=5) return json({error:'Too many incorrect attempts. Request a new code.'},429);
  if(!/^\d{6}$/.test(code) || user.verification_expires_at<now() || (await sha256(code))!==user.verification_code_hash){ await env.DB.prepare('UPDATE users SET verification_attempts=verification_attempts+1 WHERE id=?').bind(user.id).run(); return json({error:'Invalid or expired verification code.'},400); }
  await env.DB.prepare('UPDATE users SET email_verified=1, verification_code_hash=NULL, verification_expires_at=NULL, verification_attempts=0 WHERE id=?').bind(user.id).run();
  const token=await createSession(user.id,env); return withSession(json({ok:true,message:'Email verified successfully.'}),token);
}
async function resendVerification(request, env) {
  const body=await request.json(); const email=String(body.email||'').trim().toLowerCase(); const user=await env.DB.prepare('SELECT id, profile_id, email_verified, last_verification_sent_at FROM users u WHERE email=?').bind(email).first();
  if(!user) return json({ok:true,message:'If that account exists, a new code will be sent.'}); if(user.email_verified) return json({error:'Email is already verified.'},400);
  if(user.last_verification_sent_at && now()-user.last_verification_sent_at<VERIFY_RESEND_SECONDS) return json({error:`Please wait ${VERIFY_RESEND_SECONDS-(now()-user.last_verification_sent_at)} seconds before requesting another code.`},429);
  const profile=await env.DB.prepare('SELECT full_name FROM profiles WHERE id=?').bind(user.profile_id).first(); const code=randomDigits(6); await env.DB.prepare('UPDATE users SET verification_code_hash=?, verification_expires_at=?, verification_attempts=0, last_verification_sent_at=? WHERE id=?').bind(await sha256(code),now()+VERIFY_MINUTES*60,now(),user.id).run(); await sendVerificationEmail(env,email,profile?.full_name||'there',code); return json({ok:true,message:'A new verification code has been sent.'});
}
async function verifyLogin2fa(request, env) {
  const token=getPendingUser(request); if(!token) return json({error:'Your login challenge has expired. Please log in again.'},401); const ch=await env.DB.prepare('SELECT u.id AS user_id, u.twofa_enabled, u.totp_secret, u.recovery_codes_json FROM auth_challenges c JOIN users u ON u.id=c.user_id WHERE c.token_hash=? AND c.expires_at>?').bind(await sha256(token),now()).first(); if(!ch||!ch.twofa_enabled) return json({error:'Invalid login challenge.'},401);
  const code=String((await request.json()).code||'').trim(); let valid=await verifyTotp(ch.totp_secret,code); let recovery=false;
  if(!valid){ const hashes=JSON.parse(ch.recovery_codes_json||'[]'); const h=await hashRecoveryCode(code); const idx=hashes.indexOf(h); if(idx>=0){hashes.splice(idx,1); await env.DB.prepare('UPDATE users SET recovery_codes_json=? WHERE id=?').bind(JSON.stringify(hashes),ch.user_id).run(); valid=true; recovery=true;} }
  if(!valid) return json({error:'Invalid authentication code.'},401);
  await env.DB.prepare('DELETE FROM auth_challenges WHERE token_hash=?').bind(await sha256(token)).run(); const session=await createSession(ch.user_id,env); const response=withSession(json({ok:true,recovery_used:recovery}),session); const headers=new Headers(response.headers); headers.append('Set-Cookie',cookie('__Host-avelix_pending','',0)); return new Response(response.body,{status:response.status,headers});
}
async function setup2fa(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401); if(user.twofa_enabled) return json({error:'2-step verification is already enabled.'},400);
  const bytes=crypto.getRandomValues(new Uint8Array(20)); const secret=base32Encode(bytes); await env.DB.prepare('UPDATE users SET totp_secret_pending=? WHERE id=?').bind(secret,user.user_id).run(); const issuer='AVELIX'; const label=encodeURIComponent(`${issuer}:${user.login_email}`); const uri=`otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`; return json({ok:true,secret,otpauth_uri:uri});
}
async function confirm2fa(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401); const body=await request.json(); const code=String(body.code||'').trim(); const row=await env.DB.prepare('SELECT totp_secret_pending FROM users WHERE id=?').bind(user.user_id).first(); if(!row?.totp_secret_pending||!(await verifyTotp(row.totp_secret_pending,code))) return json({error:'Invalid authenticator code.'},400);
  const codes=[]; for(let i=0;i<MFA_RECOVERY_COUNT;i++) codes.push(`${randomDigits(4)}-${randomDigits(4)}`); const hashes=[]; for(const c of codes) hashes.push(await hashRecoveryCode(c)); await env.DB.prepare('UPDATE users SET twofa_enabled=1, totp_secret=?, totp_secret_pending=NULL, recovery_codes_json=? WHERE id=?').bind(row.totp_secret_pending,JSON.stringify(hashes),user.user_id).run(); return json({ok:true,recovery_codes:codes});
}
async function disable2fa(request, env) { const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401); const body=await request.json(); const row=await env.DB.prepare('SELECT totp_secret FROM users WHERE id=?').bind(user.user_id).first(); if(!row?.totp_secret||!(await verifyTotp(row.totp_secret,String(body.code||'')))) return json({error:'Invalid authenticator code.'},400); await env.DB.prepare('UPDATE users SET twofa_enabled=0,totp_secret=NULL,totp_secret_pending=NULL,recovery_codes_json=NULL WHERE id=?').bind(user.user_id).run(); return json({ok:true}); }
async function me(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ authenticated: false }, 401);
  return json({ authenticated: true, profile: user });
}

async function upgradeProfile(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const body=await request.json(); const target=String(body.target_type||'').trim().toLowerCase();
  const order={individual:0,entrepreneur:1,business:2};
  if(!['entrepreneur','business'].includes(target)) return json({error:'Invalid upgrade target.'},400);
  const current=user.account_type||'individual';
  if(order[target] <= order[current]) return json({error:'Your profile is already at this level or higher.'},400);
  if(target==='business' && !String(body.organization||'').trim()) return json({error:'Business upgrade requires a business/organization name.'},400);
  const card=target==='business'?'gold':'platinum';
  const organization=String(body.organization||user.organization||'').trim().slice(0,180);
  const industry=String(body.industry||user.industry||'').trim().slice(0,120);
  const cac=String(body.cac_number||user.cac_number||'').trim().slice(0,100);
  await env.DB.batch([
    env.DB.prepare('UPDATE profiles SET account_type=?,card_tier=?,organization=?,industry=?,cac_number=? WHERE id=?').bind(target,card,organization,industry,cac,user.id),
    env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(user.user_id,'profile.upgrade','profile',user.avx_id,JSON.stringify({from:current,to:target,card_tier:card})).run()
  ]);
  return json({ok:true,account_type:target,card_tier:card,message:`Profile upgraded to ${target}.`});
}
async function updateProfile(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Please log in.' }, 401);
  const body = await request.json();
  const fullName = String(body.full_name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  if (!fullName || !email) return json({ error: 'Name and email are required.' }, 400);
  const website = String(body.website || '').trim();
  if (website && !/^https?:\/\//i.test(website)) return json({ error: 'Website must start with http:// or https://.' }, 400);
  const other = await env.DB.prepare('SELECT id FROM users WHERE email=? AND id<>?').bind(email, user.user_id).first();
  if (other) return json({ error: 'That email is already in use.' }, 409);
  await env.DB.batch([
    env.DB.prepare(`UPDATE profiles SET full_name=?, title=?, organization=?, industry=?, location=?, email=?, phone=?, website=?, bio=?, cac_number=?, skills=?, qualifications=?, certifications=? WHERE id=?`)
      .bind(fullName, body.title || '', body.organization || '', body.industry || '', body.location || '', email, body.phone || '', website, body.bio || '', body.cac_number || '', body.skills || '', body.qualifications || '', body.certifications || '', user.id),
    env.DB.prepare('UPDATE users SET email=? WHERE id=?').bind(email, user.user_id)
  ]);
  return json({ ok: true });
}
async function revokeShare(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  await env.DB.prepare('UPDATE share_tokens SET revoked_at=? WHERE profile_id=? AND revoked_at IS NULL').bind(now(), user.id).run();
  return json({ ok: true, message: 'QR revoked.' });
}

async function generateShare(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Please log in.' }, 401);
  const body = await request.json().catch(() => ({}));
  const allowed = ['full_name','title','organization','industry','location','website','bio'];
  const fields = Array.isArray(body.fields) ? body.fields.filter(x => allowed.includes(x)) : ['full_name','title','organization','location','website'];
  if (!fields.includes('full_name')) fields.unshift('full_name');
  const token = randomToken();
  const expiresAt = now() + QR_MINUTES * 60;
  await env.DB.batch([
    env.DB.prepare('UPDATE share_tokens SET revoked_at=? WHERE profile_id=? AND revoked_at IS NULL AND expires_at>?').bind(now(), user.id, now()),
    env.DB.prepare('INSERT INTO share_tokens (profile_id, token_hash, fields_json, expires_at, max_uses) VALUES (?, ?, ?, ?, ?)').bind(user.id, await sha256(token), JSON.stringify(fields), expiresAt, QR_MAX_USES),
  ]);
  const url = new URL(request.url); url.pathname = `/s/${token}`; url.search = '';
  return json({ ok: true, url: url.toString(), expires_at: expiresAt, max_uses: QR_MAX_USES, fields });
}

async function scanShare(token, env) {
  const hash = await sha256(token);
  const ts = now();
  const result = await env.DB.prepare(`UPDATE share_tokens SET use_count=use_count+1, last_used_at=? WHERE token_hash=? AND revoked_at IS NULL AND expires_at>? AND use_count<max_uses`).bind(ts, hash, ts).run();
  if (!result.meta.changes) return renderShareExpired();
  const share = await env.DB.prepare('SELECT * FROM share_tokens WHERE token_hash=?').bind(hash).first();
  const profile = await env.DB.prepare('SELECT * FROM profiles WHERE id=?').bind(share.profile_id).first();
  if (!profile) return renderShareExpired();
  const fields = JSON.parse(share.fields_json);
  return renderPublic(profile, fields, `Secure AVELIX Share • ${profile.avx_id}`, true);
}

function renderPublic(p, fields, title, secure = false) {
  const labels = { full_name:'Full Name', title:'Role', organization:'Organization', industry:'Industry', location:'Location', website:'Website', bio:'About' };
  const rows = fields.filter(f => p[f]).map(f => `<div class="field"><span>${esc(labels[f] || f)}</span><strong>${f === 'website' ? `<a href="${esc(p[f])}" target="_blank" rel="noopener">${esc(p[f])}</a>` : esc(p[f])}</strong></div>`).join('');
  return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${styles()}</head><body><main class="public"><div class="brand">AVELIX<span>◆</span></div><section class="profile-card"><div class="eyebrow">${secure ? 'SECURE ONE-SCAN SHARE' : 'AVELIX PROFESSIONAL PROFILE'}</div><h1>${esc(p.full_name)}</h1><p class="sub">${esc(p.title || '')}${p.organization ? ` · ${esc(p.organization)}` : ''}</p><div class="status">● ${esc(p.status || 'active')}</div><div class="fields">${rows}</div><div class="idbox"><small>AVELIX ID</small><b>${esc(p.avx_id)}</b></div>${secure ? '<p class="notice">This secure QR link is valid for 30 minutes and can be scanned multiple times until it expires.</p>' : ''}</section><p class="foot">AVELIX — Prove Your Potential.</p></main></body></html>`, { headers: { 'content-type': 'text/html; charset=UTF-8' }});
}
function renderShareExpired() { return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>QR Expired • AVELIX</title>${styles()}</head><body><main class="public"><div class="brand">AVELIX<span>◆</span></div><section class="profile-card center"><div class="eyebrow">SECURE QR STATUS</div><h1>QR Expired</h1><p class="sub">This secure AVELIX QR code is no longer valid. Generate a new QR from the member dashboard.</p><div class="status bad">● EXPIRED</div></section></main></body></html>`, { status: 410, headers: { 'content-type': 'text/html; charset=UTF-8' }}); }
function styles() { return `<style>:root{--bg:#050817;--panel:#0c1430;--line:#202b50;--text:#f7f8ff;--muted:#9ca9ca;--purple:#8b4dff;--blue:#159cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#17153c 0,#050817 42%);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}.public{max-width:760px;margin:auto;padding:48px 20px}.brand{font-weight:900;font-size:26px;letter-spacing:.18em;margin-bottom:34px}.brand span{color:var(--blue);font-size:12px;margin-left:8px}.profile-card{background:linear-gradient(145deg,#111a3a,#080d21);border:1px solid var(--line);border-radius:28px;padding:34px;box-shadow:0 24px 70px #0008}.center{text-align:center}.eyebrow{font-size:11px;letter-spacing:.18em;color:#8ea3d8;font-weight:800}h1{font-size:42px;line-height:1.05;margin:14px 0 8px}.sub{color:var(--muted);font-size:17px}.status{display:inline-block;margin:18px 0;padding:8px 12px;border:1px solid #275f49;border-radius:999px;color:#67e0a1;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.status.bad{border-color:#693345;color:#ff879e}.fields{display:grid;gap:10px;margin-top:12px}.field{padding:15px;border:1px solid #1d2748;border-radius:14px;background:#070c1d}.field span{display:block;color:#7785aa;font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:5px}.field strong{font-size:15px;word-break:break-word}.field a{color:#65baff}.idbox{margin-top:18px;padding:18px;border-radius:16px;background:#0a1229;border:1px solid #27365e}.idbox small{display:block;color:#7484a8;font-size:10px;letter-spacing:.14em}.idbox b{display:block;margin-top:5px;letter-spacing:.1em}.notice{color:#ffbd68;font-size:13px}.foot{text-align:center;color:#657294;margin-top:24px;font-size:12px}</style>`; }

const appPages = {
  '/register.html': 'register', '/login.html':'login', '/verify-email.html':'verify', '/dashboard.html':'dashboard'
};
function shell(title, content, script='') { return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} • AVELIX</title>${styles()}<style>.app{max-width:1050px;margin:auto;padding:24px 18px 60px}.nav{display:flex;justify-content:space-between;align-items:center;padding:10px 0 34px}.nav a{color:#b8c3e1;text-decoration:none;margin-left:18px}.btn{border:0;border-radius:12px;padding:13px 18px;font-weight:800;cursor:pointer;color:white;background:linear-gradient(135deg,var(--purple),var(--blue));box-shadow:0 10px 30px #315bff22}.btn.ghost{background:#111a36;border:1px solid var(--line);box-shadow:none}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.panel{background:#0b122a;border:1px solid var(--line);border-radius:22px;padding:24px}.panel h2{margin-top:0}.muted{color:var(--muted)}label{display:block;font-size:12px;color:#9aa8c9;margin:13px 0 7px}input,textarea,select{width:100%;padding:13px 14px;border-radius:12px;border:1px solid #263354;background:#070d20;color:white;outline:none}textarea{min-height:100px;resize:vertical}.wide{grid-column:1/-1}.toast{margin-top:12px;color:#7ee8b1}.error{color:#ff91a5;margin-top:12px}.hero{padding:34px 0 22px}.hero h1{font-size:46px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.soon{opacity:.62;position:relative;overflow:hidden}.soon:after{content:'COMING SOON';position:absolute;top:15px;right:-31px;transform:rotate(35deg);background:#1d2850;padding:6px 38px;font-size:9px;letter-spacing:.12em}.card-showcase{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.card-image{width:100%;display:block;border-radius:18px;border:1px solid #29365c;box-shadow:0 20px 50px #0008}.soon-label{display:inline-block;margin:0 0 10px;padding:5px 9px;border-radius:999px;background:#101b3b;color:#a9b9df;font-size:9px;letter-spacing:.14em;font-weight:900}@media(max-width:760px){.card-showcase{grid-template-columns:1fr}}.qrbox{text-align:center}.qrbox canvas,.qrbox img{max-width:260px;margin:16px auto;display:block;background:white;padding:10px;border-radius:14px}.pill{display:inline-block;padding:7px 10px;border-radius:999px;background:#101b3b;color:#9eb1de;font-size:11px}.share-url{word-break:break-all;color:#73bdff;font-size:12px}.actions{display:flex;gap:10px;flex-wrap:wrap}@media(max-width:760px){.grid,.cards{grid-template-columns:1fr}.hero h1{font-size:35px}h1{font-size:34px}}</style></head><body><div class="app"><nav class="nav"><a href="/" style="font-weight:900;font-size:22px;letter-spacing:.15em;color:white">AVELIX</a><div><a href="/dashboard.html">Dashboard</a><a href="/login.html">Login</a></div></nav>${content}</div>${script}</body></html>`, {headers:{'content-type':'text/html; charset=UTF-8'}}); }
function registerPage(){return shell('Create AVELIX Account',`<section class="hero"><div class="eyebrow">JOIN AVELIX</div><h1>Create your AVELIX Account.</h1><p class="muted">Choose the identity that best describes you. You can grow from Individual to Entrepreneur and later to Business without losing your AVELIX identity.</p></section><section class="panel"><div class="grid"><div class="wide"><label>Profile type *</label><select id="account_type" onchange="toggleAccountType()"><option value="individual">Basic — Individual</option><option value="entrepreneur">Platinum — Entrepreneur / Professional</option><option value="business">Gold — Business / Organization</option></select></div><div class="wide"><label id="nameLabel">Full name *</label><input id="full_name" placeholder="Your full name"></div><div id="businessFields" class="wide" style="display:none"><div class="grid"><div><label>Business / organization name *</label><input id="organization" placeholder="Registered business or organization"></div><div><label>CAC registration number <span class="muted">(optional at registration)</span></label><input id="cac_number" placeholder="CAC / RC number"></div></div></div><div><label>Email *</label><input id="email" type="email" placeholder="you@example.com"></div><div><label>Password *</label><input id="password" type="password" placeholder="At least 8 characters"></div><div><label>Professional title</label><input id="title" placeholder="e.g. Software Developer / Founder"></div><div id="orgIndividual"><label>Organization / Business</label><input id="organization_individual" placeholder="Company, school or business"></div><div><label>Industry</label><input id="industry" placeholder="e.g. Technology"></div><div><label>Location</label><input id="location" placeholder="City, Country"></div><div><label>Phone</label><input id="phone" placeholder="Optional"></div><div><label>Website</label><input id="website" placeholder="https://..."></div><div class="wide"><label>Referral code <span class="muted">(optional)</span></label><input id="referral_code" placeholder="AVELIX-XXXXXXXX"></div><div class="wide"><label>Short bio</label><textarea id="bio" placeholder="Tell people what you do..."></textarea></div><div class="wide actions"><button class="btn" onclick="registerAccount()">Create AVELIX Account</button><span id="msg"></span></div></div></section>`,`<script>function toggleAccountType(){const type=account_type.value;const business=type==='business';businessFields.style.display=business?'block':'none';orgIndividual.style.display=business?'none':'block';nameLabel.textContent=business?'Authorized representative full name *':'Full name *'}async function registerAccount(){const type=account_type.value;const business=type==='business';const body={account_type:type,full_name:full_name.value,email:email.value,password:password.value,title:title.value,organization:business?document.getElementById('organization').value:document.getElementById('organization_individual').value,industry:industry.value,location:location.value,phone:phone.value,website:website.value,bio:bio.value,cac_number:business?cac_number.value:'',referral_code:referral_code.value};const r=await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}msg.className='toast';msg.innerHTML='Account created: <b>'+d.avx_id+'</b> — check your email for the verification code.';setTimeout(()=>location.href='/verify-email.html?email='+encodeURIComponent(email.value),700)}const ref=new URLSearchParams(location.search).get('ref');if(ref)referral_code.value=ref;toggleAccountType()</script>`);}

function verifyPage(){return shell('Verify Email',`<section class="hero"><div class="eyebrow">SECURE YOUR AVELIX ACCOUNT</div><h1>Verify your email.</h1><p class="muted">Enter the 6-digit code we sent to your email address.</p></section><section class="panel" style="max-width:560px"><label>Email</label><input id="email" type="email" placeholder="you@example.com"><label>Verification code</label><input id="code" inputmode="numeric" maxlength="6" placeholder="000000"><div class="actions" style="margin-top:18px"><button class="btn" onclick="verify()">Verify Email</button><button class="btn ghost" onclick="resend()">Resend Code</button><a class="btn ghost" href="/login.html">Login</a></div><div id="msg"></div></section>`,`<script>email.value=new URLSearchParams(location.search).get('email')||'';async function verify(){const r=await fetch('/api/verify-email',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,code:code.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}msg.className='toast';msg.textContent='Email verified. Redirecting...';setTimeout(()=>location.href='/dashboard.html',500)}async function resend(){const r=await fetch('/api/resend-verification',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value})});const d=await r.json();msg.className=r.ok?'toast':'error';msg.textContent=d.message||d.error}</script>`);}
function loginPage(){return shell('Login',`<section class="hero"><div class="eyebrow">AVELIX MEMBER ACCESS</div><h1>Welcome back.</h1><p class="muted">Access your profile, secure QR tools and member features.</p></section><section class="panel" style="max-width:560px"><label>Email</label><input id="email" type="email"><label>Password</label><input id="password" type="password"><div class="actions" style="margin-top:18px"><button class="btn" onclick="login()">Log In</button><a class="btn ghost" href="/register.html">Create Account</a></div><div id="msg"></div></section>`,`<script>async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;if(d.needs_verification)msg.innerHTML=d.error+' <a href="/verify-email.html?email='+encodeURIComponent(email.value)+'" style="color:#73bdff">Verify email</a>';return}if(d.requires_2fa){document.querySelector('.panel').innerHTML='<label>Authenticator code</label><input id="code" inputmode="numeric" maxlength="6" placeholder="000000"><div class="actions" style="margin-top:18px"><button class="btn" onclick="finish2fa()">Continue</button></div><div id="msg"></div>';return}location.href='/dashboard.html'}async function finish2fa(){const r=await fetch('/api/login/2fa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:code.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}location.href='/dashboard.html'}</script>`);}
function dashboardPage(){return shell('Dashboard',`<section class="hero"><div class="eyebrow">MY AVELIX DASHBOARD</div><h1 id="hello">Your AVELIX</h1><p class="muted">Manage your professional identity, verification, opportunities and profile growth from one place.</p><div class="actions"><button class="btn" onclick="generateQR()">Generate Secure QR</button><a class="btn ghost" href="#profile">Edit Profile</a><button class="btn ghost" onclick="logout()">Log Out</button></div></section><section class="grid"><div class="panel" id="profile"><h2>Profile</h2><div id="profileFields" class="muted">Loading...</div></div><div class="panel"><h2>PROFILE LEVEL</h2><div id="profileLevel"></div><div id="upgradeBox" style="margin-top:16px"></div></div><div class="panel qrbox"><h2>Secure QR</h2><span class="pill">Multiple scans · 30 minutes</span><div id="qr"></div><p id="qrmsg" class="muted">Generate a temporary QR when you need to share your profile.</p></div><div class="panel wide"><h2>Share My AVELIX</h2><p class="muted">Your permanent AVELIX profile can be viewed from your profile ID. Secure QR sharing is temporary and valid for 30 minutes with multiple scans.</p><a id="profileLink" class="share-url"></a></div><div class="panel"><h2>VERIFICATION CENTRE</h2><p class="muted">Build trust by verifying the information behind your professional or business identity.</p><div class="cards"><div class="field"><b>Personal Verification</b><br><small>Identity, education, employment, experience, qualifications, training and certifications.</small></div><div class="field"><b>Business Verification</b><br><small>CAC, business identity, authorized representative, licences, permits and business credentials.</small></div><div class="field soon"><b>Hard Skill Verification</b><br><span class="soon-label">COMING SOON</span><br><small>Technical and practical skills can be assessed and verified later.</small></div><div class="field soon"><b>Soft Skill Verification</b><br><span class="soon-label">COMING SOON</span><br><small>Leadership, communication, teamwork and other professional behaviours.</small></div></div><div id="credentialsPanel" style="margin-top:18px"><h3>Issued Credentials</h3><div id="credentials" class="muted">Loading credentials...</div></div></div><div class="panel"><h2>AVX WALLET</h2><p id="walletBalance" style="font-size:30px;font-weight:900;margin:8px 0">0 AVX</p><span id="walletStatus" class="pill">🔒 COMING SOON</span><p id="walletText" class="muted">AVX Credits will power future AVELIX services.</p></div><div class="panel" id="avxPackagesPanel" style="display:none"><h2>AVX PACKAGES</h2><p class="muted">Packages are controlled by AVELIX administration.</p><div id="avxPackages"></div></div><div class="panel"><h2>Your Referral Link</h2><p class="muted">Invite people to join AVELIX using your personal referral link.</p><input id="referralLink" readonly><p class="muted" id="referralCount"></p><button class="btn ghost" onclick="copyReferral()">Copy Referral Link</button></div><div class="panel"><h2>Account Security</h2><p class="muted" id="securityStatus">Loading security status...</p><div class="actions"><button class="btn ghost" onclick="start2fa()">Enable 2-Step Verification</button></div><div id="mfaBox" style="margin-top:14px"></div></div></section><section class="panel wide" id="jobSearchPanel"><h2>Find Opportunities With Your Qualifications</h2><p class="muted">AVELIX compares your skills, qualifications, certificates and verified credentials with available job requirements.</p><div class="grid"><div><label>What job are you looking for?</label><input id="jobQuery" placeholder="e.g. software developer, mechanical technician"></div><div><label>Your profile evidence</label><input id="jobEvidence" readonly></div></div><div class="actions" style="margin-top:14px"><button class="btn" onclick="findJobs()">Find Jobs</button><button class="btn ghost" onclick="findJobs(true)">Show Best Matches</button></div><div id="jobResults" style="margin-top:16px"></div></section><section class="hero"><div class="eyebrow">THE AVELIX ECOSYSTEM</div><h2>One identity that can grow with you.</h2><p class="muted">Start as an individual, grow into an entrepreneur and establish a verified business identity when your journey requires it.</p></section><section class="card-showcase"><div class="panel soon"><h3>Basic AVELIX Card</h3><span class="soon-label">INDIVIDUAL</span><img class="card-image" src="/avelix-basic-card.png" alt="AVELIX Basic Card design"><p class="muted">For individual professional identities.</p></div><div class="panel soon"><h3>Platinum AVELIX Card</h3><span class="soon-label">ENTREPRENEUR / PROFESSIONAL</span><img class="card-image" src="/avelix-platinum-card.png" alt="AVELIX Platinum Card design"><p class="muted">For entrepreneurs, independent professionals and small-business owners.</p></div><div class="panel soon"><h3>Gold AVELIX Card</h3><span class="soon-label">BUSINESS / ORGANIZATION</span><img class="card-image" src="/avelix-gold-card.png" alt="AVELIX Gold Verified Business Card design"><p class="muted">For businesses and organizations building a verified business identity.</p></div></section>`,`<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>let me,platform={settings:{}};const labels={individual:'Basic — Individual',entrepreneur:'Platinum — Entrepreneur / Professional',business:'Gold — Business / Organization'};async function load(){const r=await fetch('/api/me');if(!r.ok){location.href='/login.html';return}me=(await r.json()).profile;hello.textContent='Welcome, '+me.full_name;securityStatus.textContent=(me.email_verified?'Email verified':'Email not verified')+' • 2-Step Verification '+(me.twofa_enabled?'ON':'OFF');const type=me.account_type||'individual';profileLevel.innerHTML='<span class="pill">'+labels[type]+'</span><p class="muted" style="margin-top:10px">AVELIX ID: <b>'+esc(me.avx_id)+'</b><br>Card: '+esc((me.card_tier||type).toUpperCase())+'</p>';renderUpgrade();profileFields.innerHTML='<p><span class="pill">'+me.avx_id+'</span> <span class="pill">'+esc(labels[type])+'</span></p><p><b>'+esc(me.full_name)+'</b><br>'+[me.title,me.organization,me.location].filter(Boolean).map(esc).join(' · ')+'</p><label>Update profile</label><input id="full_name" value="'+attr(me.full_name)+'"><input id="title" style="margin-top:8px" value="'+attr(me.title)+'" placeholder="Professional title"><input id="organization" style="margin-top:8px" value="'+attr(me.organization)+'" placeholder="Organization / business"><input id="industry" style="margin-top:8px" value="'+attr(me.industry)+'" placeholder="Industry"><input id="location" style="margin-top:8px" value="'+attr(me.location)+'" placeholder="Location"><input id="phone" style="margin-top:8px" value="'+attr(me.phone)+'" placeholder="Phone"><input id="website" style="margin-top:8px" value="'+attr(me.website)+'" placeholder="Website"><input id="cac_number" style="margin-top:8px" value="'+attr(me.cac_number)+'" placeholder="CAC registration number"><input id="skills" style="margin-top:8px" value="'+attr(me.skills)+'" placeholder="Skills: Python, CAD, marketing, project management"><textarea id="qualifications" style="margin-top:8px" placeholder="Qualifications: B.Sc. Computer Science, HND Mechanical Engineering...">'+txt(me.qualifications)+'</textarea><textarea id="certifications" style="margin-top:8px" placeholder="Certificates: AWS, Cisco, PMP, trade certificates...">'+txt(me.certifications)+'</textarea><textarea id="bio" style="margin-top:8px">'+txt(me.bio)+'</textarea><button class="btn" style="margin-top:10px" onclick="save()">Save Changes</button>';profileLink.href='/v/'+me.avx_id;profileLink.textContent=location.origin+'/v/'+me.avx_id;referralLink.value=location.origin+'/register.html?ref='+encodeURIComponent(me.referral_code||'');referralCount.textContent=(me.referral_count||0)+' referral'+((me.referral_count||0)===1?'':'s')+' joined AVELIX';const cr=await fetch('/api/credentials');const cd=await cr.json();credentials.innerHTML=(cd.credentials||[]).map(c=>'<div class="field"><b>'+esc(c.title)+'</b><br><span class="pill">'+esc(c.status.toUpperCase())+'</span> · '+esc(c.issuer||'Issuer pending')+'<br><small>'+esc(c.credential_id)+'</small><br><a class="share-url" href="/c/'+encodeURIComponent(c.credential_id)+'" target="_blank">Open verification page</a></div>').join('')||'<p>No credentials have been issued yet.</p>';await loadPlatform();jobEvidence.value=[me.skills,me.qualifications,me.certifications].filter(Boolean).join(' • ')||'Add your skills, qualifications or certificates above.'}function renderUpgrade(){const type=me.account_type||'individual';if(type==='business'){upgradeBox.innerHTML='<span class="pill">GOLD PROFILE ACTIVE</span><p class="muted">Your personal AVELIX identity is connected to a business-level profile.</p>';return}if(type==='individual'){upgradeBox.innerHTML='<p class="muted">Ready to grow beyond a Basic profile?</p><button class="btn" onclick="upgradeProfile(\'entrepreneur\')">Upgrade to Platinum</button><p class="muted" style="margin-top:10px">Entrepreneur / Professional</p>';return}upgradeBox.innerHTML='<span class="pill">PLATINUM PROFILE</span><p class="muted">You can establish your business identity when ready.</p><button class="btn" onclick="upgradeProfile(\'business\')">Upgrade to Gold Business</button>'}async function upgradeProfile(target){let body={target_type:target};if(target==='business'){const organization=prompt('Enter your business / organization name:',me.organization||'');if(!organization)return;const industry=prompt('Enter your business industry:',me.industry||'');body.organization=organization||me.organization;body.industry=industry||me.industry;const cac=prompt('Enter CAC / RC number if available (optional):',me.cac_number||'');body.cac_number=cac||me.cac_number}const r=await fetch('/api/profile/upgrade',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok){alert(d.error);return}alert(d.message);load()}function esc(s){return String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}function attr(s){return String(s||'').replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;')}function txt(s){return String(s||'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}async function loadPlatform(){const r=await fetch('/api/platform');platform=await r.json();const s=platform.settings||{};walletBalance.textContent=(me.avx_balance||0)+' AVX';if(s.avx_enabled==='1'){walletStatus.textContent='● LIVE';walletText.textContent='AVX Credits are available for eligible AVELIX services.';avxPackagesPanel.style.display='block';avxPackages.innerHTML=(platform.packages||[]).map(p=>'<div class="field" style="margin-bottom:10px"><b>'+esc(p.name)+'</b><br><span class="pill">₦'+Number(p.price_ngn).toLocaleString()+' · '+Number(p.avx_amount).toLocaleString()+' AVX</span><p class="muted">'+esc(p.description||'')+'</p></div>').join('')||'<p class="muted">No active packages are available yet.</p>'}else{walletStatus.textContent='🔒 COMING SOON';walletText.textContent='AVX Credits will power future AVELIX services.';avxPackagesPanel.style.display='none'}if(s.job_search_enabled!=='1')jobSearchPanel.style.display='none'}async function save(){const r=await fetch('/api/profile',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({full_name:full_name.value,title:title.value,bio:bio.value,email:me.login_email||me.email,organization:organization.value,industry:industry.value,location:location.value,phone:phone.value,website:website.value,cac_number:cac_number.value,skills:skills.value,qualifications:qualifications.value,certifications:certifications.value})});const d=await r.json();if(!r.ok){alert(d.error||'Unable to save');return}await load();alert('Profile saved.')}async function generateQR(){const r=await fetch('/api/share',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({fields:['full_name','title','organization','industry','location','website','bio']})});const d=await r.json();if(!r.ok){qrmsg.className='error';qrmsg.textContent=d.error;return}qr.innerHTML='';new QRCode(qr,{text:d.url,width:230,height:230});qrmsg.innerHTML='<b>Valid for 30 minutes · multiple scans.</b><br>'+new Date(d.expires_at*1000).toLocaleString()+'<br><span class="share-url">'+d.url+'</span><br><br><button class="btn ghost" onclick="generateQR()">Generate New QR</button>'}async function findJobs(best=false){const q=best?'':jobQuery.value;const r=await fetch('/api/jobs/recommendations?q='+encodeURIComponent(q));const d=await r.json();if(!r.ok){jobResults.innerHTML='<p class="error">'+(d.error||'Unable to search jobs')+'</p>';return}jobResults.innerHTML=(d.jobs||[]).map(j=>'<div class="field" style="margin-bottom:10px"><b>'+esc(j.title)+'</b><br><span class="muted">'+esc(j.employer)+' · '+esc(j.location||'')+'</span><br><span class="pill">'+esc(j.match_reason)+'</span><p class="muted">'+esc(j.employment_type||'')+' · '+esc(j.work_mode||'')+' · '+Number(j.min_experience||0)+'+ yrs experience</p><small>Skills: '+esc(j.required_skills||'Not specified')+'<br>Qualifications: '+esc(j.required_qualifications||'Not specified')+'<br>Certificates: '+esc(j.required_certificates||'Not specified')+'</small><br>'+(j.apply_url?'<a class="btn ghost" style="display:inline-block;margin-top:10px;text-decoration:none" href="'+attr(j.apply_url)+'" target="_blank" rel="noopener">Apply</a>':'')+'</div>').join('')||'<p class="muted">No strong matches yet. Add more skills, qualifications or certificates to your profile.</p>'}async function copyReferral(){await navigator.clipboard.writeText(referralLink.value);alert('Referral link copied.')}async function start2fa(){const r=await fetch('/api/2fa/setup',{method:'POST'});const d=await r.json();if(!r.ok){alert(d.error);return}mfaBox.innerHTML='<p class="muted">1. Add an authenticator app. 2. Enter this setup key: <b>'+esc(d.secret)+'</b>. 3. Enter the 6-digit code below.</p><input id="mfaCode" inputmode="numeric" maxlength="6" placeholder="000000"><button class="btn" style="margin-top:10px" onclick="confirm2fa()">Confirm & Enable</button>'}async function confirm2fa(){const r=await fetch('/api/2fa/confirm',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:mfaCode.value})});const d=await r.json();if(!r.ok){alert(d.error);return}mfaBox.innerHTML='<p><b>Save these recovery codes somewhere secure. Each can be used once:</b></p><pre style="white-space:pre-wrap">'+d.recovery_codes.join('\n')+'</pre>';securityStatus.textContent='Email verified • 2-Step Verification ON';alert('2-Step Verification enabled. Save your recovery codes.')}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/'}load()</script>`);}

async function getSettings(env) {
  const rows = await env.DB.prepare('SELECT key,value FROM platform_settings').all();
  const out = {};
  for (const r of (rows.results || [])) out[r.key] = r.value;
  return out;
}
async function platformConfig(request, env) {
  const settings = await getSettings(env);
  const packages = settings.avx_enabled === '1' ? await env.DB.prepare('SELECT id,name,price_ngn,avx_amount,description FROM avx_packages WHERE active=1 ORDER BY sort_order,id').all() : {results:[]};
  return json({settings, packages: packages.results || []});
}
async function adminPlatform(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const settings=await getSettings(env);
  const packages=await env.DB.prepare('SELECT * FROM avx_packages ORDER BY sort_order,id').all();
  const profiles=await env.DB.prepare('SELECT avx_id,full_name,email,avx_balance,account_type,card_tier,organization,cac_number FROM profiles ORDER BY created_at DESC').all();
  const transactions=await env.DB.prepare(`SELECT t.*,p.avx_id,p.full_name FROM avx_transactions t JOIN profiles p ON p.id=t.profile_id ORDER BY t.created_at DESC LIMIT 100`).all();
  const jobs=await env.DB.prepare('SELECT * FROM jobs ORDER BY created_at DESC').all();
  const treasury=await env.DB.prepare('SELECT * FROM avx_treasury WHERE id=1').first();
  return json({settings,packages:packages.results||[],profiles:profiles.results||[],transactions:transactions.results||[],jobs:jobs.results||[],treasury:treasury||null});
}
async function adminSetSetting(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const key=String(b.key||'').trim(); const allowed=['avx_enabled','global_search_enabled','verified_credentials_enabled','verify_mark_enabled','cards_enabled','job_search_enabled'];
  if(!allowed.includes(key)) return json({error:'Invalid platform setting.'},400);
  const value=b.value ? '1' : '0';
  await env.DB.prepare(`INSERT INTO platform_settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`).bind(key,value).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'platform.setting','setting',key,JSON.stringify({value})).run();
  return json({ok:true,key,value});
}
async function adminSavePackage(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const name=String(b.name||'').trim().slice(0,80); const price=Math.max(0,Math.floor(Number(b.price_ngn)||0)); const amount=Math.max(0,Math.floor(Number(b.avx_amount)||0)); const description=String(b.description||'').trim().slice(0,240); const active=b.active?1:0; const sort=Math.floor(Number(b.sort_order)||0);
  if(!name||!price||!amount) return json({error:'Package name, price and AVX amount are required.'},400);
  if(b.id){ await env.DB.prepare('UPDATE avx_packages SET name=?,price_ngn=?,avx_amount=?,description=?,active=?,sort_order=? WHERE id=?').bind(name,price,amount,description,active,sort,Number(b.id)).run(); }
  else { await env.DB.prepare('INSERT INTO avx_packages (name,price_ngn,avx_amount,description,active,sort_order) VALUES (?,?,?,?,?,?)').bind(name,price,amount,description,active,sort).run(); }
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'package.save','avx_package',String(b.id||'new'),JSON.stringify({name,price,amount,active})).run();
  return json({ok:true});
}
async function adminDeletePackage(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const id=Number((await request.json()).id||0); if(!id) return json({error:'Package id required.'},400);
  await env.DB.prepare('DELETE FROM avx_packages WHERE id=?').bind(id).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'package.delete','avx_package',String(id),'{}').run();
  return json({ok:true});
}
async function adminCreditWallet(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const avx=String(b.avx_id||'').trim().toUpperCase(); const amount=Math.floor(Number(b.amount)||0); const reference=String(b.reference||'').trim().slice(0,120); const note=String(b.note||'').trim().slice(0,240);
  if(!avx||amount<=0) return json({error:'Valid AVELIX ID and positive AVX amount are required.'},400);
  const p=await env.DB.prepare('SELECT id,avx_id,full_name,avx_balance FROM profiles WHERE avx_id=?').bind(avx).first(); if(!p) return json({error:'Profile not found.'},404);
  const treasury=await env.DB.prepare('SELECT * FROM avx_treasury WHERE id=1').first();
  if(!treasury) return json({error:'AVX treasury is not configured. Run the AVX treasury migration first.'},500);
  if(Number(treasury.locked)===1 || Number(treasury.unlocked_amount)<=Number(treasury.issued_amount)) return json({error:'AVX treasury is locked. Unlock AVX supply before crediting member wallets.'},403);
  const available=Number(treasury.unlocked_amount)-Number(treasury.issued_amount);
  if(amount>available) return json({error:'Credit exceeds the currently unlocked AVX supply. Available to issue: '+available.toLocaleString()+' AVX.'},400);
  const newBalance=Number(p.avx_balance||0)+amount;
  const newIssued=Number(treasury.issued_amount)+amount;
  await env.DB.batch([
    env.DB.prepare('UPDATE profiles SET avx_balance=avx_balance+? WHERE id=?').bind(amount,p.id),
    env.DB.prepare('UPDATE avx_treasury SET issued_amount=?,updated_at=CURRENT_TIMESTAMP WHERE id=1').bind(newIssued),
    env.DB.prepare('INSERT INTO avx_transactions (profile_id,type,amount,reference,note,created_by_admin_email) VALUES (?,?,?,?,?,?)').bind(p.id,'credit',amount,reference,note,admin.login_email),
    env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'wallet.credit','profile',p.avx_id,JSON.stringify({amount,reference,note,newIssued}))
  ]);
  return json({ok:true,new_balance:newBalance,issued_amount:newIssued,available_to_issue:Number(treasury.unlocked_amount)-newIssued});
}
async function adminUnlockTreasury(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const amount=Math.floor(Number(b.amount)||0);
  if(amount<=0) return json({error:'Enter a positive AVX amount to unlock.'},400);
  const treasury=await env.DB.prepare('SELECT * FROM avx_treasury WHERE id=1').first();
  if(!treasury) return json({error:'AVX treasury is not configured. Run the AVX treasury migration first.'},500);
  const max=Number(treasury.max_supply); const current=Number(treasury.unlocked_amount); const issued=Number(treasury.issued_amount);
  if(current+amount>max) return json({error:'Unlock exceeds the 1,000,000,000 AVX maximum supply.'},400);
  const unlocked=current+amount;
  await env.DB.batch([
    env.DB.prepare('UPDATE avx_treasury SET unlocked_amount=?,locked=0,updated_at=CURRENT_TIMESTAMP WHERE id=1').bind(unlocked),
    env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'treasury.unlock','avx_treasury','1',JSON.stringify({amount,unlocked,issued}))
  ]);
  return json({ok:true,max_supply:max,unlocked_amount:unlocked,issued_amount:issued,available_to_issue:unlocked-issued});
}
async function adminJobs(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const rows=await env.DB.prepare('SELECT * FROM jobs ORDER BY created_at DESC').all(); return json({jobs:rows.results||[]});
}
async function adminSaveJob(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied(); const b=await request.json();
  const title=String(b.title||'').trim().slice(0,140), employer=String(b.employer||'').trim().slice(0,140); if(!title||!employer) return json({error:'Job title and employer are required.'},400);
  const vals=[title,employer,String(b.location||'').slice(0,120),String(b.work_mode||'').slice(0,40),String(b.employment_type||'').slice(0,40),String(b.required_skills||'').slice(0,500),String(b.required_qualifications||'').slice(0,500),String(b.required_certificates||'').slice(0,500),Math.max(0,Math.floor(Number(b.min_experience)||0)),String(b.apply_url||'').slice(0,500),b.active?1:0];
  if(b.id) await env.DB.prepare('UPDATE jobs SET title=?,employer=?,location=?,work_mode=?,employment_type=?,required_skills=?,required_qualifications=?,required_certificates=?,min_experience=?,apply_url=?,active=? WHERE id=?').bind(...vals,Number(b.id)).run();
  else await env.DB.prepare('INSERT INTO jobs (title,employer,location,work_mode,employment_type,required_skills,required_qualifications,required_certificates,min_experience,apply_url,active) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(...vals).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'job.save','job',String(b.id||'new'),JSON.stringify({title,employer})).run(); return json({ok:true});
}
async function adminDeleteJob(request, env) { const admin=await requireAdmin(request,env); if(!admin) return adminDenied(); const id=Number((await request.json()).id||0); if(!id) return json({error:'Job id required.'},400); await env.DB.prepare('DELETE FROM jobs WHERE id=?').bind(id).run(); return json({ok:true}); }
function tokens(text){ return new Set(String(text||'').toLowerCase().split(/[^a-z0-9+#.]+/).filter(x=>x.length>2)); }
async function jobRecommendations(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401); const settings=await getSettings(env); if(settings.job_search_enabled!=='1') return json({enabled:false,jobs:[]});
  const q=new URL(request.url).searchParams.get('q')||''; const jobs=(await env.DB.prepare('SELECT * FROM jobs WHERE active=1 ORDER BY created_at DESC').all()).results||[];
  const verified=settings.verified_credentials_enabled==='1' ? ((await env.DB.prepare(`SELECT title,credential_type,status FROM credentials WHERE profile_id=? AND status='verified'`).bind(user.id).all()).results||[]) : [];
  const profileText=[user.title,user.industry,user.skills,user.qualifications,user.certifications,...verified.flatMap(c=>[c.title,c.credential_type])].join(' '); const have=tokens(profileText); const query=tokens(q);
  const ranked=jobs.map(j=>{const required=tokens([j.title,j.required_skills,j.required_qualifications,j.required_certificates].join(' ')); let score=0; for(const t of required){if(have.has(t)) score+=2; if(query.has(t)) score+=1;} if(user.title&&String(j.title).toLowerCase().includes(String(user.title).toLowerCase())) score+=3; return {...j,match_score:score,match_reason:score>=6?'Strong match':score>=3?'Good match':'Related opportunity'} }).filter(j=>!q || j.match_score>0).sort((a,b)=>b.match_score-a.match_score).slice(0,20);
  return json({enabled:true,profile_basis:{skills:user.skills||'',qualifications:user.qualifications||'',certifications:user.certifications||'',verified_credentials:verified},jobs:ranked});
}

async function myCredentials(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const rows=await env.DB.prepare('SELECT credential_id,credential_type,title,issuer,reference,status,verified_at,expires_at,notes,created_at FROM credentials WHERE profile_id=? ORDER BY created_at DESC').bind(user.id).all();
  return json({credentials:rows.results||[]});
}
async function requireAdmin(request, env) {
  const user = await currentUser(request, env);
  if (!user) return null;
  if (!env.ADMIN_EMAIL || String(user.login_email).toLowerCase() !== String(env.ADMIN_EMAIL).toLowerCase()) return null;
  return user;
}
function adminDenied(){ return json({error:'Admin access required.'},403); }
async function adminCredentials(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const rows=await env.DB.prepare(`SELECT c.*, p.full_name, p.avx_id, p.account_type FROM credentials c JOIN profiles p ON p.id=c.profile_id ORDER BY c.created_at DESC`).all();
  return json({credentials:rows.results||[]});
}
async function adminCreateCredential(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const avx=String(b.avx_id||'').trim().toUpperCase();
  const p=await env.DB.prepare('SELECT id,full_name,avx_id FROM profiles WHERE avx_id=?').bind(avx).first(); if(!p) return json({error:'Profile not found.'},404);
  const type=String(b.credential_type||'credential').trim().slice(0,80); const title=String(b.title||'').trim().slice(0,160); const issuer=String(b.issuer||'').trim().slice(0,160);
  if(!title) return json({error:'Credential title is required.'},400);
  const status=['pending','verified','expired','revoked','unverified'].includes(b.status)?b.status:'pending';
  const id=makeId();
  await env.DB.prepare(`INSERT INTO credentials (credential_id,profile_id,credential_type,title,issuer,reference,status,verified_at,expires_at,notes,created_by_admin_email) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).bind(id,p.id,type,title,issuer,String(b.reference||'').slice(0,160),status,status==='verified'?now():null,b.expires_at?Number(b.expires_at):null,String(b.notes||'').slice(0,500),admin.login_email).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'credential.create','credential',id,JSON.stringify({status,title,avx_id:avx})).run();
  return json({ok:true,credential_id:id},201);
}
async function adminUpdateCredential(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const id=String(b.credential_id||'').trim(); const status=String(b.status||'');
  if(!['pending','verified','expired','revoked','unverified'].includes(status)) return json({error:'Invalid credential status.'},400);
  const row=await env.DB.prepare('SELECT * FROM credentials WHERE credential_id=?').bind(id).first(); if(!row) return json({error:'Credential not found.'},404);
  await env.DB.prepare('UPDATE credentials SET status=?, verified_at=? WHERE credential_id=?').bind(status,status==='verified'?now():null,id).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'credential.status','credential',id,JSON.stringify({from:row.status,to:status})).run();
  return json({ok:true});
}
async function publicCredential(request, env, id) {
  const c=await env.DB.prepare(`SELECT c.*,p.full_name,p.avx_id,p.organization,p.title AS profile_title FROM credentials c JOIN profiles p ON p.id=c.profile_id WHERE c.credential_id=?`).bind(id).first();
  if(!c) return new Response('Credential not found',{status:404});
  const status=c.status==='verified'?'VERIFIED':String(c.status||'UNVERIFIED').toUpperCase();
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(c.title)} • AVELIX</title>${styles()}</head><body><main class="public"><div class="brand">AVELIX<span>◆</span></div><section class="profile-card"><div class="eyebrow">AVELIX VERIFIED CREDENTIAL</div><h1>${esc(c.title)}</h1><p class="sub">${esc(c.full_name)}${c.organization?' · '+esc(c.organization):''}</p><div class="status ${c.status==='verified'?'':'bad'}">● ${esc(status)}</div><div class="fields"><div class="field"><span>Credential Type</span><strong>${esc(c.credential_type)}</strong></div><div class="field"><span>Issuer</span><strong>${esc(c.issuer||'Not provided')}</strong></div><div class="field"><span>Credential ID</span><strong>${esc(c.credential_id)}</strong></div><div class="field"><span>Verification Date</span><strong>${c.verified_at?new Date(c.verified_at*1000).toLocaleString():'Not yet verified'}</strong></div></div><div class="idbox"><small>AVELIX PROFILE</small><b>${esc(c.avx_id)}</b></div><p class="foot">Status reflects the current AVELIX verification record.</p></section></main></body></html>`,{headers:{'content-type':'text/html;charset=UTF-8'}});
}
function adminPage(){return shell('AVELIX Admin Control Center',`<section class="hero"><div class="eyebrow">AVELIX ADMIN</div><h1>Platform Control Center</h1><p class="muted">Control AVX, packages, feature launches, job listings, wallet credits and credential verification without changing or redeploying the website.</p></section><section class="panel"><h2>Feature Launch Controls</h2><div id="settings" class="grid"></div></section><section class="grid" style="margin-top:16px"><div class="panel"><h2>AVX Package Manager</h2><div class="grid"><div><label>Package name</label><input id="pname" placeholder="Starter"></div><div><label>Price (NGN)</label><input id="pprice" type="number" placeholder="5000"></div><div><label>AVX amount</label><input id="pamount" type="number" placeholder="50"></div><div><label>Sort order</label><input id="psort" type="number" value="0"></div><div class="wide"><label>Description</label><input id="pdesc" placeholder="AVX credit package"></div><div><label>Active</label><select id="pactive"><option value="1">Yes</option><option value="0">No</option></select></div></div><button class="btn" style="margin-top:14px" onclick="savePackage()">Create Package</button><div id="packages" style="margin-top:16px"></div></div><div class="panel"><h2>AVX Treasury</h2><div id="treasuryBox" class="field">Loading treasury...</div><p class="muted">The initial 1 billion AVX reserve is created now but remains locked. Member wallets cannot receive AVX until you deliberately unlock supply.</p><label>Unlock amount later</label><input id="unlockAmount" type="number" placeholder="e.g. 1000000"><button class="btn ghost" style="margin-top:10px" onclick="unlockTreasury()">Unlock Supply</button><div id="treasuryMsg"></div></div><div class="panel"><h2>Credit AVX to Member</h2><label>Member AVELIX ID</label><input id="wavx" placeholder="AVX-..."><label>Amount</label><input id="wamount" type="number" placeholder="100"><label>Payment/reference</label><input id="wref" placeholder="Payment reference"><label>Note</label><input id="wnote" placeholder="Manual credit after payment confirmation"><button class="btn" style="margin-top:14px" onclick="creditWallet()">Credit Wallet</button><div id="walletMsg"></div><div id="members" style="margin-top:16px"></div></div></section><section class="panel" style="margin-top:16px"><h2>Job Listings Manager</h2><p class="muted">Add or maintain opportunities used by the AVELIX qualification matching engine.</p><div class="grid"><div><label>Job title</label><input id="jtitle" placeholder="Software Developer"></div><div><label>Employer</label><input id="jemployer" placeholder="Company name"></div><div><label>Location</label><input id="jlocation" placeholder="Kaduna / Remote"></div><div><label>Work mode</label><input id="jmode" placeholder="Remote / Onsite / Hybrid"></div><div><label>Employment type</label><input id="jtype" placeholder="Full-time"></div><div><label>Minimum experience</label><input id="jexp" type="number" value="0"></div><div class="wide"><label>Required skills</label><input id="jskills" placeholder="Python, JavaScript, SQL"></div><div class="wide"><label>Required qualifications</label><input id="jquals" placeholder="B.Sc. Computer Science, HND..."></div><div class="wide"><label>Required certificates</label><input id="jcerts" placeholder="AWS, Cisco, PMP..."></div><div class="wide"><label>Application URL</label><input id="jurl" placeholder="https://..."></div><div><label>Active</label><select id="jactive"><option value="1">Yes</option><option value="0">No</option></select></div></div><button class="btn" style="margin-top:14px" onclick="saveJob()">Add Job</button><div id="jobs" style="margin-top:16px"></div></section><section class="panel" style="margin-top:16px"><h2>Issue Credential</h2><div class="grid"><div><label>Member AVELIX ID</label><input id="cavx" placeholder="AVX-..."></div><div><label>Credential title</label><input id="ctitle" placeholder="B.Sc. Computer Science"></div><div><label>Credential type</label><input id="ctype" placeholder="Education"></div><div><label>Issuer</label><input id="cissuer" placeholder="University / Employer"></div><div><label>Reference</label><input id="cref"></div><div><label>Initial status</label><select id="cstatus"><option value="pending">Pending</option><option value="verified">Verified</option><option value="unverified">Unverified</option></select></div></div><button class="btn" style="margin-top:14px" onclick="createCredential()">Issue Credential</button><div id="credentialMsg"></div><div id="credentialsAdmin" style="margin-top:16px" class="muted">Loading...</div></section>`,`<script>let data;const labels={avx_enabled:'AVX Credits',global_search_enabled:'Global Search',verified_credentials_enabled:'Verified Credentials',verify_mark_enabled:'Verify Credential Mark',cards_enabled:'AVELIX Cards',job_search_enabled:'Job Search'};const esc=(s)=>String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));async function load(){const r=await fetch('/api/admin/platform');if(r.status===403){document.body.innerHTML='<main class="public"><section class="profile-card"><h1>Admin access required</h1><p class="sub">Set ADMIN_EMAIL to your AVELIX account email in Worker variables.</p></section></main>';return}data=await r.json();settings.innerHTML=Object.entries(labels).map(([k,v])=>'<div class="field"><b>'+v+'</b><br><span class="pill">'+(data.settings[k]==='1'?'LIVE':'COMING SOON')+'</span><br><button class="btn ghost" style="margin-top:10px" onclick="toggleSetting(\''+k+'\','+(data.settings[k]==='1'?'false':'true')+')">'+(data.settings[k]==='1'?'Turn Off':'Launch')+'</button></div>').join('');packages.innerHTML=(data.packages||[]).map(p=>'<div class="field"><b>'+esc(p.name)+'</b> · ₦'+Number(p.price_ngn).toLocaleString()+' · '+Number(p.avx_amount).toLocaleString()+' AVX<br><small>'+esc(p.description||'')+' · '+(p.active?'ACTIVE':'DRAFT')+'</small><br><button class="btn ghost" onclick="editPackage('+p.id+')">Edit</button> <button class="btn ghost" onclick="deletePackage('+p.id+')">Delete</button></div>').join('')||'<p class="muted">No packages yet.</p>';members.innerHTML=(data.profiles||[]).slice(0,20).map(p=>'<div class="field"><b>'+esc(p.full_name)+'</b><br>'+esc(p.avx_id)+' · '+esc((p.account_type||'individual').toUpperCase())+' · '+esc((p.card_tier||'basic').toUpperCase())+' · '+Number(p.avx_balance||0)+' AVX</div>').join('');const t=data.treasury;if(t){const max=Number(t.max_supply||0),unlocked=Number(t.unlocked_amount||0),issued=Number(t.issued_amount||0);treasuryBox.innerHTML='<b>Maximum supply:</b> '+max.toLocaleString()+' AVX<br><b>Unlocked:</b> '+unlocked.toLocaleString()+' AVX<br><b>Issued:</b> '+issued.toLocaleString()+' AVX<br><b>Available to issue:</b> '+Math.max(0,unlocked-issued).toLocaleString()+' AVX<br><span class="pill">'+(Number(t.locked)===1?'🔒 LOCKED':'● UNLOCKED')+'</span>'}jobs.innerHTML=(data.jobs||[]).map(j=>'<div class="field"><b>'+esc(j.title)+'</b> · '+esc(j.employer)+'<br><small>'+esc(j.location||'')+' · '+(j.active?'ACTIVE':'OFF')+' · '+esc(j.required_skills||'')+'</small><br><button class="btn ghost" onclick="toggleJob('+j.id+','+(!j.active)+')">'+(j.active?'Deactivate':'Activate')+'</button> <button class="btn ghost" onclick="deleteJob('+j.id+')">Delete</button></div>').join('')||'<p class="muted">No job listings.</p>';const cr=await fetch('/api/admin/credentials');const cd=await cr.json();credentialsAdmin.innerHTML=(cd.credentials||[]).map(c=>'<div class="field"><b>'+esc(c.full_name)+' · '+esc(c.title)+'</b><br><span class="pill">'+esc(c.status.toUpperCase())+'</span> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'verified\')">Verify</button> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'revoked\')">Revoke</button> <a class="share-url" href="/c/'+encodeURIComponent(c.credential_id)+'" target="_blank">Public page</a></div>').join('')||'<p class="muted">No credentials.</p>'}async function toggleSetting(key,value){const r=await fetch('/api/admin/platform/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key,value})});if(!r.ok)alert((await r.json()).error);load()}async function savePackage(){const b={id:window.editingPackage||null,name:pname.value,price_ngn:pprice.value,avx_amount:pamount.value,description:pdesc.value,active:pactive.value==='1',sort_order:psort.value};const r=await fetch('/api/admin/packages',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok){alert(d.error);return}window.editingPackage=null;pname.value='';pprice.value='';pamount.value='';pdesc.value='';psort.value='0';pactive.value='1';load()}function editPackage(id){const p=data.packages.find(x=>x.id===id);if(!p)return;window.editingPackage=id;pname.value=p.name;pprice.value=p.price_ngn;pamount.value=p.avx_amount;pdesc.value=p.description||'';pactive.value=p.active?'1':'0';psort.value=p.sort_order||0;document.querySelector('#pname').scrollIntoView({behavior:'smooth'})}async function deletePackage(id){if(!confirm('Delete this package?'))return;await fetch('/api/admin/packages/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}async function unlockTreasury(){const amount=Number(unlockAmount.value||0);if(!amount||amount<=0){treasuryMsg.className='error';treasuryMsg.textContent='Enter a valid unlock amount.';return}if(!confirm('Unlock '+amount.toLocaleString()+' AVX from the locked treasury?'))return;const r=await fetch('/api/admin/treasury/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({amount})});const d=await r.json();treasuryMsg.className=r.ok?'toast':'error';treasuryMsg.textContent=r.ok?'Unlocked '+Number(d.available_to_issue).toLocaleString()+' AVX available for issuance.':d.error;unlockAmount.value='';load()}async function creditWallet(){const r=await fetch('/api/admin/wallet/credit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({avx_id:wavx.value,amount:wamount.value,reference:wref.value,note:wnote.value})});const d=await r.json();walletMsg.className=r.ok?'toast':'error';walletMsg.textContent=r.ok?'Wallet credited. New balance: '+d.new_balance+' AVX':d.error;load()}async function saveJob(){const b={title:jtitle.value,employer:jemployer.value,location:jlocation.value,work_mode:jmode.value,employment_type:jtype.value,min_experience:jexp.value,required_skills:jskills.value,required_qualifications:jquals.value,required_certificates:jcerts.value,apply_url:jurl.value,active:jactive.value==='1'};const r=await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok){alert(d.error);return}['jtitle','jemployer','jlocation','jmode','jtype','jexp','jskills','jquals','jcerts','jurl'].forEach(id=>document.getElementById(id).value='');load()}async function toggleJob(id,on){const j=data.jobs.find(x=>x.id===id);if(!j)return;const b={id,title:j.title,employer:j.employer,location:j.location,work_mode:j.work_mode,employment_type:j.employment_type,min_experience:j.min_experience,required_skills:j.required_skills,required_qualifications:j.required_qualifications,required_certificates:j.required_certificates,apply_url:j.apply_url,active:on};await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});load()}async function deleteJob(id){if(!confirm('Delete this job?'))return;await fetch('/api/admin/jobs/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}async function createCredential(){const b={avx_id:cavx.value,title:ctitle.value,credential_type:ctype.value,issuer:cissuer.value,reference:cref.value,status:cstatus.value};const r=await fetch('/api/admin/credentials',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();credentialMsg.className=r.ok?'toast':'error';credentialMsg.textContent=r.ok?'Created '+d.credential_id:d.error;if(r.ok){cavx.value=ctitle.value=ctype.value=cissuer.value=cref.value='';load()}}async function setCredential(id,status){const r=await fetch('/api/admin/credentials/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_id:id,status})});if(!r.ok)alert((await r.json()).error);load()}load()</script>`)}

export default { async fetch(request, env) {
  const url = new URL(request.url);
  try {
    if (url.pathname === '/api/register' && request.method === 'POST') return await register(request, env);
    if (url.pathname === '/api/verify-email' && request.method === 'POST') return await verifyEmail(request, env);
    if (url.pathname === '/api/resend-verification' && request.method === 'POST') return await resendVerification(request, env);
    if (url.pathname === '/api/login' && request.method === 'POST') return await login(request, env);
    if (url.pathname === '/api/login/2fa' && request.method === 'POST') return await verifyLogin2fa(request, env);
    if (url.pathname === '/api/2fa/setup' && request.method === 'POST') return await setup2fa(request, env);
    if (url.pathname === '/api/2fa/confirm' && request.method === 'POST') return await confirm2fa(request, env);
    if (url.pathname === '/api/2fa/disable' && request.method === 'POST') return await disable2fa(request, env);
    if (url.pathname === '/api/platform' && request.method === 'GET') return await platformConfig(request, env);
    if (url.pathname === '/api/jobs/recommendations' && request.method === 'GET') return await jobRecommendations(request, env);
    if (url.pathname === '/api/admin/platform' && request.method === 'GET') return await adminPlatform(request, env);
    if (url.pathname === '/api/admin/platform/settings' && request.method === 'POST') return await adminSetSetting(request, env);
    if (url.pathname === '/api/admin/packages' && request.method === 'POST') return await adminSavePackage(request, env);
    if (url.pathname === '/api/admin/packages/delete' && request.method === 'POST') return await adminDeletePackage(request, env);
    if (url.pathname === '/api/admin/wallet/credit' && request.method === 'POST') return await adminCreditWallet(request, env);
    if (url.pathname === '/api/admin/treasury/unlock' && request.method === 'POST') return await adminUnlockTreasury(request, env);
    if (url.pathname === '/api/admin/jobs' && request.method === 'GET') return await adminJobs(request, env);
    if (url.pathname === '/api/admin/jobs' && request.method === 'POST') return await adminSaveJob(request, env);
    if (url.pathname === '/api/admin/jobs/delete' && request.method === 'POST') return await adminDeleteJob(request, env);
    if (url.pathname === '/api/credentials' && request.method === 'GET') return await myCredentials(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'GET') return await adminCredentials(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'POST') return await adminCreateCredential(request, env);
    if (url.pathname === '/api/admin/credentials/status' && request.method === 'POST') return await adminUpdateCredential(request, env);
    if (url.pathname === '/api/logout' && request.method === 'POST') return await logout(request, env);
    if (url.pathname === '/api/me') return await me(request, env);
    if (url.pathname === '/api/profile' && request.method === 'PUT') return await updateProfile(request, env);
    if (url.pathname === '/api/profile/upgrade' && request.method === 'POST') return await upgradeProfile(request, env);
    if (url.pathname === '/api/share' && request.method === 'POST') return await generateShare(request, env);
    if (url.pathname.startsWith('/s/')) return await scanShare(url.pathname.slice(3), env);
    if (url.pathname.startsWith('/c/')) return await publicCredential(request, env, url.pathname.slice(3));
    if (url.pathname === '/admin.html') { const a=await requireAdmin(request,env); return a ? adminPage() : new Response('Admin access required',{status:403}); }
    if (url.pathname.startsWith('/v/')) { const p=await env.DB.prepare('SELECT * FROM profiles WHERE avx_id=?').bind(url.pathname.slice(3)).first(); return p ? renderPublic(p,['full_name','title','organization','industry','location','website','bio','account_type','card_tier'],'AVELIX Profile') : new Response('Profile not found',{status:404}); }
    if (appPages[url.pathname] === 'register') return registerPage();
    if (appPages[url.pathname] === 'login') return loginPage();
    if (appPages[url.pathname] === 'verify') return verifyPage();
    if (appPages[url.pathname] === 'dashboard') return dashboardPage();
    return env.ASSETS.fetch(request);
  } catch (e) { return json({ error: 'Server error. Please try again.', detail: e?.message || String(e) }, 500); }
}};
