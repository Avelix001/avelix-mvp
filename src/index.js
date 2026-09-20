import { RINGO_DEFAULT_COST, RINGO_ALLOWED_CREDENTIAL_TYPES, RINGO_ALLOWED_MIME, RINGO_ACTIVE_STATUSES, RINGO_ACTIVE_REQUEST_STATUSES, makeVerificationReference, canVerificationTransition } from './Ringo.js';
const SESSION_COOKIE = '__Host-avelyx_session';
const SESSION_DAYS = 7;
const QR_MINUTES = 30;
const QR_MAX_USES = 1;
const REFERRAL_PREFIX = 'AVELYX';
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
  const safeName = esc(name); const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:30px;background:#071025;color:#fff"><div style="font-size:24px;font-weight:900;letter-spacing:4px">AVELYX</div><h1>Verify your email</h1><p>Hello ${safeName}, use this code to verify your AVELYX account:</p><div style="font-size:34px;font-weight:900;letter-spacing:10px;background:#111b3d;padding:18px;text-align:center;border-radius:14px">${code}</div><p>This code expires in ${VERIFY_MINUTES} minutes. If you did not create this account, you can ignore this email.</p></div>`;
  await sendEmail(env,email,'Verify your AVELYX email',html,`Your AVELYX verification code is ${code}. It expires in ${VERIFY_MINUTES} minutes.`);
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
  if (!fullName || !email) return json({ error: 'Name and email are required.' }, 400);
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}/.test(password)) {
    return json({ error: 'Password must be at least 8 characters and include uppercase, lowercase and a number.' }, 400);
  }
  if (accountType === 'business' && !organization) return json({ error: 'Business accounts require a business name.' }, 400);
  const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (exists) return json({ error: 'An account with this email already exists. Please log in.' }, 409);

  const avxId = makeId();
  const myReferralCode = `${REFERRAL_PREFIX}-${crypto.randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()}`;
  const hash = await passwordHash(password);

  const profileResult = await env.DB.prepare(`INSERT INTO profiles (avx_id, account_type, card_tier, full_name, title, organization, industry, location, email, phone, website, bio, status, cac_number, referral_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`)
    .bind(avxId, accountType, accountType === 'business' ? 'gold' : accountType === 'entrepreneur' ? 'platinum' : 'basic', fullName, body.title || '', organization, body.industry || '', body.location || '', email, body.phone || '', body.website || '', body.bio || '', cacNumber, myReferralCode).run();

  const profileId = profileResult.meta?.last_row_id;
  if (!profileId) throw new Error('Could not create AVELYX profile.');

  let userId;
  try {
    const userResult = await env.DB.prepare('INSERT INTO users (profile_id, email, password_hash, email_verified) VALUES (?, ?, ?, 1)').bind(profileId, email, hash).run();
    userId = userResult.meta?.last_row_id;
    if (!userId) throw new Error('Could not create AVELYX account.');
  } catch (e) {
    await env.DB.prepare('DELETE FROM profiles WHERE id=?').bind(profileId).run();
    throw e;
  }

  const token = await createSession(userId, env);
  return withSession(json({ ok: true, avx_id: avxId, message: 'Account created successfully.' }, 201), token);
}
async function cardEligibility(user, env) {
  const p = await env.DB.prepare('SELECT * FROM profiles WHERE id=?').bind(user.user_id ? user.id : user.profile_id).first();
  const profile = p || user;
  const tier = profile.card_tier || (profile.account_type==='business'?'gold':profile.account_type==='entrepreneur'?'platinum':'basic');
  const required = [
    ['full_name','Full name'],['title','Professional title'],['location','Location'],['phone','Phone'],
    ['skills','Skills'],['qualifications','Qualifications'],['certifications','Certifications']
  ];
  const missing = required.filter(([k]) => !String(profile[k]||'').trim()).map(([,label])=>label);
  if (profile.account_type === 'business') {
    if (!String(profile.organization||'').trim()) missing.push('Business / organization name');
    if (!String(profile.cac_number||'').trim()) missing.push('CAC / RC number');
  }
  let verifiedCount = 0;
  try { const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM credentials WHERE profile_id=? AND status='verified'").bind(profile.id).first(); verifiedCount = Number(row?.n||0); } catch(e) {}
  if (verifiedCount < 1) missing.push('At least one verified credential');
  return { eligible: missing.length===0, card_tier:tier, missing };
}
async function cardPurchase(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({error:'Please log in.'},401);
  const settings=await getSettings(env);
  if(settings.cards_enabled!=='1') return json({error:'AVELYX Cards are not currently launched. Your card eligibility can still be prepared for a future launch.'},403);
  const eligibility = await cardEligibility(user, env);
  if (!eligibility.eligible) return json({ok:false,eligible:false,card_tier:eligibility.card_tier,missing:eligibility.missing,error:'Verify all required information and documents before purchasing your AVELYX card.'},403);
  const reference = `CARD-${crypto.randomUUID().replaceAll('-','').slice(0,16).toUpperCase()}`;
  await env.DB.prepare('INSERT INTO card_orders (user_id,profile_id,card_tier,status,reference) VALUES (?,?,?,?,?)').bind(user.user_id,user.id,eligibility.card_tier,'pending_payment',reference).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(user.user_id,'card.purchase.started','profile',user.avx_id,JSON.stringify({card_tier:eligibility.card_tier,reference})).run();
  return json({ok:true,eligible:true,card_tier:eligibility.card_tier,status:'pending_payment',reference,message:'You are eligible for this AVELYX card. Continue to payment to complete your order.'},201);
}
async function cardStatus(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const eligibility=await cardEligibility(user,env);
  const orders=await env.DB.prepare('SELECT id,card_tier,status,reference,created_at FROM card_orders WHERE user_id=? ORDER BY id DESC LIMIT 5').bind(user.user_id).all();
  return json({eligible:eligibility.eligible,card_tier:eligibility.card_tier,missing:eligibility.missing,orders:orders.results||[]});
}
async function login(request, env) {
  const body = await request.json(); const email = String(body.email || '').trim().toLowerCase(); const password = String(body.password || '');
  const user = await env.DB.prepare('SELECT id, profile_id, password_hash, email_verified FROM users WHERE email=?').bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) return json({ error: 'Invalid email or password.' }, 401);
  const token = await createSession(user.id, env); return withSession(json({ ok: true }), token);
}

function withPendingSession(response, token, maxAge = LOGIN_CHALLENGE_MINUTES * 60) {
  const headers = new Headers(response.headers); headers.append('Set-Cookie', cookie('__Host-avelyx_pending', token, maxAge)); return new Response(response.body,{status:response.status,headers});
}
function getPendingUser(request) { return getCookie(request,'__Host-avelyx_pending'); }
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
  await env.DB.prepare('DELETE FROM auth_challenges WHERE token_hash=?').bind(await sha256(token)).run(); const session=await createSession(ch.user_id,env); const response=withSession(json({ok:true,recovery_used:recovery}),session); const headers=new Headers(response.headers); headers.append('Set-Cookie',cookie('__Host-avelyx_pending','',0)); return new Response(response.body,{status:response.status,headers});
}
async function setup2fa(request, env) {
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401); if(user.twofa_enabled) return json({error:'2-step verification is already enabled.'},400);
  const bytes=crypto.getRandomValues(new Uint8Array(20)); const secret=base32Encode(bytes); await env.DB.prepare('UPDATE users SET totp_secret_pending=? WHERE id=?').bind(secret,user.user_id).run(); const issuer='AVELYX'; const label=encodeURIComponent(`${issuer}:${user.login_email}`); const uri=`otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`; return json({ok:true,secret,otpauth_uri:uri});
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
  return json({error:'Account level is selected during registration. Individual accounts do not have a self-upgrade option.'},403);
}

async function ensureProfileMediaTables(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS profile_photos (profile_id INTEGER PRIMARY KEY,mime_type TEXT NOT NULL,data_base64 TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS profile_locks (profile_id INTEGER PRIMARY KEY,locked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)`).run();
}
async function profileIsLocked(env, profileId){ await ensureProfileMediaTables(env); return !!(await env.DB.prepare('SELECT profile_id FROM profile_locks WHERE profile_id=?').bind(profileId).first()); }
async function profilePhoto(request, env){
  await ensureProfileMediaTables(env); const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const row=await env.DB.prepare('SELECT mime_type,data_base64 FROM profile_photos WHERE profile_id=?').bind(user.id).first();
  if(!row) return new Response('Not found',{status:404});
  try { const bytes=Uint8Array.from(atob(row.data_base64),c=>c.charCodeAt(0)); return new Response(bytes,{headers:{'content-type':row.mime_type,'cache-control':'private, max-age=300'}}); } catch(e){ return new Response('Invalid photo',{status:500}); }
}
async function uploadProfilePhoto(request, env){
  await ensureProfileMediaTables(env); const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const existing=await env.DB.prepare('SELECT profile_id FROM profile_photos WHERE profile_id=?').bind(user.id).first();
  if(existing) return json({error:'Profile photo already uploaded. Photo replacement is locked for the MVP.'},409);
  if(await profileIsLocked(env,user.id)) return json({error:'Unlock your profile before uploading your photo.'},423);
  const b=await request.json().catch(()=>({})); const mime=String(b.mime_type||'').toLowerCase(); const data=String(b.data_base64||'');
  if(!['image/jpeg','image/png','image/webp'].includes(mime)) return json({error:'Upload JPG, PNG or WebP only.'},400);
  if(!data || data.length>700000) return json({error:'Photo is missing or too large. Keep it under about 500 KB.'},400);
  await env.DB.prepare('INSERT INTO profile_photos(profile_id,mime_type,data_base64) VALUES(?,?,?)').bind(user.id,mime,data).run();
  await env.DB.prepare('INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)').bind(user.user_id,'profile.photo.upload','profile',user.avx_id,JSON.stringify({mime_type:mime})).run();
  return json({ok:true});
}
async function lockProfile(request, env, unlock=false){
  await ensureProfileMediaTables(env); const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  if(unlock){ await env.DB.prepare('DELETE FROM profile_locks WHERE profile_id=?').bind(user.id).run(); return json({ok:true,locked:false}); }
  await env.DB.prepare('INSERT OR IGNORE INTO profile_locks(profile_id) VALUES(?)').bind(user.id).run();
  return json({ok:true,locked:true});
}
async function updateProfile(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Please log in.' }, 401);
  if (await profileIsLocked(env,user.id)) return json({ error: 'Profile is locked. Tap Edit Profile to unlock it before making changes.' }, 423);
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
  const data=await getDigitalCV({headers:new Headers()},env,profile.avx_id); return data ? new Response(`<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>AVELYX Digital CV • ${esc(profile.avx_id)}</title>${styles()}${digitalCVStyles()}</head><body><div class=\"app\"><main class=\"app-content\">${digitalCVMarkup(data,true)}</main></div></body></html>`,{headers:{'content-type':'text/html;charset=UTF-8'}}) : renderShareExpired();
}


const PERMISSION_FIELDS = ['full_name','title','organization','industry','location','website','bio','phone','skills','qualifications','certifications','cac_number'];
const PERMISSION_LABELS = {full_name:'Full name',title:'Professional title',organization:'Organization',industry:'Industry',location:'Location',website:'Website',bio:'About',phone:'Phone',skills:'Skills',qualifications:'Qualifications',certifications:'Certifications',cac_number:'CAC / RC number'};
function safePermissionFields(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(v=>String(v)).filter(v=>PERMISSION_FIELDS.includes(v)))].slice(0,12);
}
async function createInformationRequest(request, env) {
  const requester = await currentUser(request, env);
  if (!requester) return json({error:'Please log in before requesting information.'},401);
  const body = await request.json().catch(()=>({}));
  const avxId = String(body.avx_id||'').trim().toUpperCase();
  const fields = safePermissionFields(body.requested_fields);
  const reason = String(body.reason||'').trim().slice(0,500);
  if (!avxId) return json({error:'Enter the participant AVELYX ID.'},400);
  if (!fields.length) return json({error:'Select at least one information field.'},400);
  const target = await env.DB.prepare('SELECT id,avx_id,full_name FROM profiles WHERE avx_id=?').bind(avxId).first();
  if (!target) return json({error:'Participant not found.'},404);
  if (target.id === requester.id) return json({error:'You cannot request permission from your own profile.'},400);
  const requesterName = requester.full_name || requester.login_email || 'AVELYX member';
  const requesterEmail = requester.login_email || requester.email || '';
  const existing = await env.DB.prepare(`SELECT id FROM information_requests WHERE requester_user_id=? AND profile_id=? AND status='pending' AND expires_at>? LIMIT 1`).bind(requester.user_id,target.id,now()).first();
  if (existing) return json({error:'You already have a pending information request for this participant.'},409);
  const expiresAt = now() + 7*86400;
  const result = await env.DB.prepare(`INSERT INTO information_requests (requester_user_id,requester_name,requester_email,profile_id,request_type,requested_fields,reason,status,expires_at) VALUES (?,?,?,?,?,?,?,?,?)`)
    .bind(requester.user_id,requesterName,requesterEmail,target.id,'profile',JSON.stringify(fields),reason,'pending',expiresAt).run();
  await env.DB.prepare(`INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)`).bind(requester.user_id,'information.request','profile',target.avx_id,JSON.stringify({request_id:result.meta?.last_row_id,fields})).run();
  return json({ok:true,request_id:result.meta?.last_row_id,message:'Information request sent. The participant must approve it before protected information is shared.'},201);
}
async function informationRequests(request, env) {
  const user = await currentUser(request,env);
  if (!user) return json({error:'Please log in.'},401);
  const rows = await env.DB.prepare(`SELECT r.*,p.avx_id,p.full_name AS participant_name FROM information_requests r JOIN profiles p ON p.id=r.profile_id WHERE r.profile_id=? ORDER BY CASE WHEN r.status='pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 100`).bind(user.id).all();
  const requests=(rows.results||[]).map(r=>({...r,requested_fields:JSON.parse(r.requested_fields||'[]'),approved_fields:JSON.parse(r.approved_fields||'[]')}));
  return json({ok:true,requests,pending_count:requests.filter(r=>r.status==='pending' && (!r.expires_at || r.expires_at>now())).length});
}
async function sentInformationRequests(request, env) {
  const user = await currentUser(request,env);
  if (!user) return json({error:'Please log in.'},401);
  const rows = await env.DB.prepare(`SELECT r.*,p.avx_id,p.full_name AS participant_name FROM information_requests r JOIN profiles p ON p.id=r.profile_id WHERE r.requester_user_id=? ORDER BY r.created_at DESC LIMIT 100`).bind(user.user_id).all();
  const requests=(rows.results||[]).map(r=>({...r,requested_fields:JSON.parse(r.requested_fields||'[]'),approved_fields:JSON.parse(r.approved_fields||'[]')}));
  return json({ok:true,requests});
}
async function respondInformationRequest(request, env, requestId) {
  const user = await currentUser(request,env);
  if (!user) return json({error:'Please log in.'},401);
  const body = await request.json().catch(()=>({}));
  const decision = String(body.decision||'').trim().toLowerCase();
  if (!['accepted','declined'].includes(decision)) return json({error:'Choose accept or decline.'},400);
  const row = await env.DB.prepare(`SELECT * FROM information_requests WHERE id=? AND profile_id=?`).bind(Number(requestId),user.id).first();
  if (!row) return json({error:'Information request not found.'},404);
  if (row.status !== 'pending') return json({error:'This request has already been answered.'},409);
  if (row.expires_at && row.expires_at<=now()) {
    await env.DB.prepare(`UPDATE information_requests SET status='expired',responded_at=? WHERE id=?`).bind(now(),row.id).run();
    return json({error:'This information request has expired.'},410);
  }
  const requested = safePermissionFields(JSON.parse(row.requested_fields||'[]'));
  const approved = decision==='accepted' ? safePermissionFields(body.approved_fields).filter(f=>requested.includes(f)) : [];
  if (decision==='accepted' && !approved.length) return json({error:'Select at least one field to approve.'},400);
  await env.DB.prepare(`UPDATE information_requests SET status=?,approved_fields=?,responded_at=? WHERE id=?`).bind(decision,JSON.stringify(approved),now(),row.id).run();
  await env.DB.prepare(`INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)`).bind(user.user_id,`information.${decision}`,'information_request',String(row.id),JSON.stringify({requester_user_id:row.requester_user_id,approved_fields:approved})).run();
  return json({ok:true,status:decision,approved_fields:approved,message:decision==='accepted'?'Information permission granted for the selected fields.':'Information request declined.'});
}
async function permittedInformation(request, env, requestId) {
  const user = await currentUser(request,env);
  if (!user) return json({error:'Please log in.'},401);
  const row = await env.DB.prepare(`SELECT r.*,p.* FROM information_requests r JOIN profiles p ON p.id=r.profile_id WHERE r.id=? AND r.requester_user_id=?`).bind(Number(requestId),user.user_id).first();
  if (!row) return json({error:'Information request not found.'},404);
  if (row.status!=='accepted') return json({error:'Information has not been approved.'},403);
  if (row.expires_at && row.expires_at<=now()) return json({error:'This permission has expired.'},410);
  const fields=safePermissionFields(JSON.parse(row.approved_fields||'[]'));
  const data={avx_id:row.avx_id};
  for (const f of fields) if (row[f]) data[f]=row[f];
  await env.DB.prepare(`INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)`).bind(user.user_id,'information.access','information_request',String(row.id),JSON.stringify({fields})).run();
  return json({ok:true,request_id:row.id,participant:{avx_id:row.avx_id,full_name:row.full_name},fields,data});
}

function renderPublic(p, fields, title, secure = false) {
  const labels = { full_name:'Full Name', title:'Role', organization:'Organization', industry:'Industry', location:'Location', website:'Website', bio:'About' };
  const rows = fields.filter(f => p[f]).map(f => `<div class="field"><span>${esc(labels[f] || f)}</span><strong>${f === 'website' ? `<a href="${esc(p[f])}" target="_blank" rel="noopener">${esc(p[f])}</a>` : esc(p[f])}</strong></div>`).join('');
  return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${styles()}</head><body><main class="public"><div class="brand">AVELYX<span>◆</span></div><section class="profile-card"><div class="eyebrow">${secure ? 'SECURE ONE-SCAN SHARE' : 'AVELYX PROFESSIONAL PROFILE'}</div><h1>${esc(p.full_name)}</h1><p class="sub">${esc(p.title || '')}${p.organization ? ` · ${esc(p.organization)}` : ''}</p><div class="status">● ${esc(p.status || 'active')}</div><div class="fields">${rows}</div><div class="idbox"><small>AVELYX ID</small><b>${esc(p.avx_id)}</b></div>${secure ? '<p class="notice">This secure QR link is valid for 30 minutes and expires after one successful scan.</p>' : ''}</section><p class="foot">AVELYX — Prove Your Potential.</p></main></body></html>`, { headers: { 'content-type': 'text/html; charset=UTF-8' }});
}
function renderShareExpired() { return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>QR Expired • AVELYX</title>${styles()}</head><body><main class="public"><div class="brand">AVELYX<span>◆</span></div><section class="profile-card center"><div class="eyebrow">SECURE QR STATUS</div><h1>QR Expired</h1><p class="sub">This secure AVELYX QR code is no longer valid. Generate a new QR from the member dashboard.</p><div class="status bad">● EXPIRED</div></section></main></body></html>`, { status: 410, headers: { 'content-type': 'text/html; charset=UTF-8' }}); }

async function ensureInstitutionTables(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS institutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    state TEXT,
    country TEXT NOT NULL DEFAULT 'Nigeria',
    institution_type TEXT,
    status TEXT NOT NULL DEFAULT 'onboarding',
    verification_method TEXT DEFAULT 'manual',
    processing_time TEXT DEFAULT 'Up to 3 working days',
    contact_name TEXT,
    contact_email TEXT,
    contact_phone TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_institutions_status ON institutions(status,name)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS institution_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    institution_name TEXT NOT NULL,
    state TEXT,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'requested',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_institution_requests_status ON institution_requests(status,created_at)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS verification_submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    institution_id INTEGER NOT NULL,
    credential_type TEXT NOT NULL,
    qualification TEXT NOT NULL,
    programme TEXT,
    graduation_year TEXT,
    reference TEXT,
    file_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    data_base64 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'submitted',
    avx_cost INTEGER NOT NULL DEFAULT 10,
    notes TEXT,
    institution_response TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(institution_id) REFERENCES institutions(id) ON DELETE RESTRICT
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_verification_submissions_profile ON verification_submissions(profile_id,created_at)`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_verification_submissions_status ON verification_submissions(status,created_at)`).run();
}


async function ensureAdminControlTables(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_wallet (id INTEGER PRIMARY KEY CHECK(id=1), balance INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO admin_wallet(id,balance) VALUES(1,0)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS credential_pricing (id INTEGER PRIMARY KEY AUTOINCREMENT, credential_type TEXT NOT NULL UNIQUE, avx_cost INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  for(const type of RINGO_ALLOWED_CREDENTIAL_TYPES) await env.DB.prepare(`INSERT OR IGNORE INTO credential_pricing(credential_type,avx_cost,active) VALUES(?,?,0)`).bind(type,0).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS agents (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT, phone TEXT, state TEXT, role TEXT NOT NULL DEFAULT 'Agent', status TEXT NOT NULL DEFAULT 'active', notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status,name)`).run();
}
async function credentialPrice(env, credentialType){
  await ensureAdminControlTables(env);
  const type=String(credentialType||'').trim().toLowerCase();
  const row=await env.DB.prepare(`SELECT avx_cost,active FROM credential_pricing WHERE credential_type=?`).bind(type).first();
  if(!row || Number(row.active)!==1 || Number(row.avx_cost)<=0) return 0;
  return Math.max(1,Math.min(100000,Math.floor(Number(row.avx_cost))));
}
async function verificationPrices(request, env){
  await ensureAdminControlTables(env);
  const rows=await env.DB.prepare(`SELECT credential_type,avx_cost,active FROM credential_pricing ORDER BY id`).all();
  return json({prices:rows.results||[],avx_ngn_rate:100});
}
async function adminCredentialPrices(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  await ensureAdminControlTables(env);
  const rows=await env.DB.prepare(`SELECT credential_type,avx_cost,active,updated_at FROM credential_pricing ORDER BY id`).all();
  return json({prices:rows.results||[],avx_ngn_rate:100});
}
async function adminSaveCredentialPrice(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  await ensureAdminControlTables(env);
  const b=await request.json().catch(()=>({}));
  const type=String(b.credential_type||'').trim().toLowerCase();
  const cost=Math.floor(Number(b.avx_cost)||0); const active=b.active?1:0;
  if(!RINGO_ALLOWED_CREDENTIAL_TYPES.includes(type)) return json({error:'Invalid credential type.'},400);
  if(cost<0 || cost>100000) return json({error:'AVX price must be between 0 and 100,000.'},400);
  await env.DB.prepare(`INSERT INTO credential_pricing(credential_type,avx_cost,active,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(credential_type) DO UPDATE SET avx_cost=excluded.avx_cost,active=excluded.active,updated_at=CURRENT_TIMESTAMP`).bind(type,cost,active).run();
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'credential.price.update','credential_pricing',type,JSON.stringify({avx_cost:cost,active})).run();
  return json({ok:true,credential_type:type,avx_cost:cost,active});
}
async function adminAdjustWallet(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  await ensureAdminControlTables(env);
  const b=await request.json().catch(()=>({}));
  const avx=String(b.avx_id||'').trim().toUpperCase(); const delta=Math.floor(Number(b.amount)||0);
  const reference=String(b.reference||'').trim().slice(0,120); const note=String(b.note||'').trim().slice(0,240);
  if(!avx || !delta) return json({error:'Enter an AVELYX ID and a non-zero AVX adjustment.'},400);
  const member=await env.DB.prepare(`SELECT id,avx_id,full_name,avx_balance FROM profiles WHERE avx_id=?`).bind(avx).first(); if(!member) return json({error:'Profile not found.'},404);
  const treasury=await env.DB.prepare(`SELECT * FROM avx_treasury WHERE id=1`).first();
  const adminWallet=await env.DB.prepare(`SELECT balance FROM admin_wallet WHERE id=1`).first();
  const current=Number(member.avx_balance||0);
  if(delta>0){
    if(!treasury || Number(treasury.locked)===1) return json({error:'AVX treasury is locked. Unlock supply before adding AVX.'},403);
    const available=Number(treasury.unlocked_amount)-Number(treasury.issued_amount); if(delta>available) return json({error:`Only ${available.toLocaleString()} AVX is currently available to issue.`},400);
    await env.DB.batch([
      env.DB.prepare(`UPDATE profiles SET avx_balance=avx_balance+? WHERE id=?`).bind(delta,member.id),
      env.DB.prepare(`UPDATE avx_treasury SET issued_amount=issued_amount+?,updated_at=CURRENT_TIMESTAMP WHERE id=1`).bind(delta),
      env.DB.prepare(`INSERT INTO avx_transactions(profile_id,type,amount,reference,note,created_by_admin_email) VALUES(?,?,?,?,?,?)`).bind(member.id,'admin_adjustment',delta,reference,note||'Admin AVX adjustment',admin.login_email),
      env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'wallet.adjust','profile',member.avx_id,JSON.stringify({delta,reference,note}))
    ]);
  }else{
    const remove=Math.abs(delta); if(current<remove) return json({error:`Member only has ${current.toLocaleString()} AVX available.`},400);
    await env.DB.batch([
      env.DB.prepare(`UPDATE profiles SET avx_balance=avx_balance-? WHERE id=? AND avx_balance>=?`).bind(remove,member.id,remove),
      env.DB.prepare(`UPDATE admin_wallet SET balance=balance+?,updated_at=CURRENT_TIMESTAMP WHERE id=1`).bind(remove),
      env.DB.prepare(`INSERT INTO avx_transactions(profile_id,type,amount,reference,note,created_by_admin_email) VALUES(?,?,?,?,?,?)`).bind(member.id,'admin_adjustment',-remove,reference,note||'Admin AVX debit',admin.login_email),
      env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'wallet.adjust','profile',member.avx_id,JSON.stringify({delta,reference,note}))
    ]);
  }
  const fresh=await env.DB.prepare(`SELECT avx_balance FROM profiles WHERE id=?`).bind(member.id).first(); const aw=await env.DB.prepare(`SELECT balance FROM admin_wallet WHERE id=1`).first();
  return json({ok:true,new_balance:Number(fresh?.avx_balance||0),admin_wallet_balance:Number(aw?.balance||0)});
}
async function adminAgents(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied(); await ensureAdminControlTables(env);
  const rows=await env.DB.prepare(`SELECT * FROM agents ORDER BY created_at DESC`).all(); return json({agents:rows.results||[]});
}
async function adminSaveAgent(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied(); await ensureAdminControlTables(env);
  const b=await request.json().catch(()=>({})); const id=Number(b.id||0); const name=String(b.name||'').trim().slice(0,140); if(!name)return json({error:'Agent name is required.'},400);
  const email=String(b.email||'').trim().slice(0,180),phone=String(b.phone||'').trim().slice(0,60),state=String(b.state||'').trim().slice(0,80),role=String(b.role||'Agent').trim().slice(0,80),status=['active','inactive'].includes(String(b.status))?String(b.status):'active',notes=String(b.notes||'').trim().slice(0,500);
  if(id) await env.DB.prepare(`UPDATE agents SET name=?,email=?,phone=?,state=?,role=?,status=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(name,email,phone,state,role,status,notes,id).run();
  else await env.DB.prepare(`INSERT INTO agents(name,email,phone,state,role,status,notes) VALUES(?,?,?,?,?,?,?)`).bind(name,email,phone,state,role,status,notes).run();
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'agent.save','agent',String(id||name),JSON.stringify({name,status,role})).run(); return json({ok:true});
}
async function adminDeleteAgent(request, env){const admin=await requireAdmin(request,env);if(!admin)return adminDenied();await ensureAdminControlTables(env);const id=Number((await request.json()).id||0);if(!id)return json({error:'Agent id required.'},400);await env.DB.prepare(`DELETE FROM agents WHERE id=?`).bind(id).run();return json({ok:true});}
async function adminCardOrders(request, env){
  const admin=await requireAdmin(request,env); if(!admin)return adminDenied();
  const rows=await env.DB.prepare(`SELECT c.*,p.full_name,p.avx_id,p.account_type FROM card_orders c JOIN profiles p ON p.id=c.profile_id ORDER BY c.id DESC LIMIT 100`).all();
  return json({orders:rows.results||[]});
}
async function adminCardStatus(request, env){
  const admin=await requireAdmin(request,env); if(!admin)return adminDenied();
  const b=await request.json().catch(()=>({})); const id=Number(b.id||0); const status=String(b.status||'').trim();
  if(!id || !['approved','rejected','issued'].includes(status)) return json({error:'Invalid card order update.'},400);
  const row=await env.DB.prepare(`SELECT * FROM card_orders WHERE id=?`).bind(id).first(); if(!row)return json({error:'Card order not found.'},404);
  await env.DB.prepare(`UPDATE card_orders SET status=? WHERE id=?`).bind(status,id).run();
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'card.status','card_order',String(id),JSON.stringify({from:row.status,to:status})).run();
  return json({ok:true,status});
}
async function adminApproveVerificationPayment(request, env){
  const admin=await requireAdmin(request,env); if(!admin)return adminDenied(); await ensureAdminControlTables(env);
  const b=await request.json().catch(()=>({})); const id=Number(b.id||0); const decision=String(b.decision||'').trim().toLowerCase();
  if(!id || !['approve','reject'].includes(decision)) return json({error:'Choose approve or reject.'},400);
  const row=await env.DB.prepare(`SELECT v.*,p.avx_balance,p.avx_id,i.name institution_name FROM verification_submissions v JOIN profiles p ON p.id=v.profile_id JOIN institutions i ON i.id=v.institution_id WHERE v.id=?`).bind(id).first(); if(!row)return json({error:'Verification request not found.'},404);
  if(row.status!=='pending_payment') return json({error:'This payment is no longer awaiting approval.'},409);
  if(decision==='reject'){await env.DB.prepare(`UPDATE verification_submissions SET status='rejected',notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind('Payment approval was declined by AVELYX admin.',id).run();await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'verification.payment.reject','verification_submission',String(id),'{}').run();return json({ok:true,status:'rejected'});}
  const cost=Number(row.avx_cost||0); if(cost<=0)return json({error:'No active AVX price is configured for this credential type.'},400);
  if(Number(row.avx_balance||0)<cost)return json({error:`Member balance is ${Number(row.avx_balance||0)} AVX; ${cost} AVX is required.`},402);
  const debit=await env.DB.prepare(`UPDATE profiles SET avx_balance=avx_balance-? WHERE id=? AND avx_balance>=?`).bind(cost,row.profile_id,cost).run(); if(Number(debit.meta?.changes||0)!==1)return json({error:'Unable to debit the member wallet.'},409);
  await env.DB.batch([
    env.DB.prepare(`UPDATE admin_wallet SET balance=balance+?,updated_at=CURRENT_TIMESTAMP WHERE id=1`).bind(cost),
    env.DB.prepare(`UPDATE verification_submissions SET status='submitted',updated_at=CURRENT_TIMESTAMP,notes=? WHERE id=?`).bind('Payment approved and AVX collected. Verification is now submitted for processing.',id),
    env.DB.prepare(`INSERT INTO avx_transactions(profile_id,type,amount,reference,note,created_by_admin_email) VALUES(?,?,?,?,?,?)`).bind(row.profile_id,'verification_charge',-cost,row.reference,`Credential verification at ${row.institution_name}`,admin.login_email),
    env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'verification.payment.approve','verification_submission',String(id),JSON.stringify({cost,reference:row.reference,institution:row.institution_name}))
  ]);
  return json({ok:true,status:'submitted',charged:cost});
}
async function verificationCost(env){
  try { const row=await env.DB.prepare("SELECT value FROM platform_settings WHERE key='verification_cost_avx'").first(); const n=Math.floor(Number(row?.value||0)); return Math.max(0,Math.min(100000,n)); } catch(e){ return 0; }
}
async function adminVerificationCost(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json().catch(()=>({})); const cost=Math.floor(Number(b.cost||0));
  if(!cost || cost<1 || cost>100000) return json({error:'Verification cost must be between 1 and 100,000 AVX.'},400);
  await env.DB.prepare(`INSERT INTO platform_settings(key,value,updated_at) VALUES('verification_cost_avx',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`).bind(String(cost)).run();
  await env.DB.prepare('INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)').bind(admin.user_id,'verification.cost.update','setting','verification_cost_avx',JSON.stringify({cost})).run();
  return json({ok:true,cost});
}
async function adminVerificationDocument(request, env){
  const admin=await requireAdmin(request,env); if(!admin) return new Response('Admin access required',{status:403});
  await ensureInstitutionTables(env); const id=Number(new URL(request.url).searchParams.get('id')||0);
  const row=await env.DB.prepare('SELECT file_name,mime_type,data_base64 FROM verification_submissions WHERE id=?').bind(id).first();
  if(!row) return new Response('Document not found',{status:404});
  try { const bytes=Uint8Array.from(atob(row.data_base64),c=>c.charCodeAt(0)); return new Response(bytes,{headers:{'content-type':row.mime_type,'content-disposition':`inline; filename="${String(row.file_name||'document').replace(/[^a-zA-Z0-9._-]/g,'_')}"`,'cache-control':'private, no-store'}}); } catch(e){ return new Response('Invalid document',{status:500}); }
}
async function institutionsList(request, env){
  await ensureInstitutionTables(env);
  const rows=await env.DB.prepare(`SELECT id,name,state,country,institution_type,status,verification_method,processing_time FROM institutions WHERE status='active' ORDER BY name`).all();
  return json({institutions:rows.results||[]});
}

async function requestInstitution(request, env){
  await ensureInstitutionTables(env);
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const b=await request.json().catch(()=>({}));
  const name=String(b.institution_name||'').trim().slice(0,180), state=String(b.state||'').trim().slice(0,80), reason=String(b.reason||'').trim().slice(0,500);
  if(!name) return json({error:'Institution name is required.'},400);
  const existing=await env.DB.prepare(`SELECT id FROM institution_requests WHERE profile_id=? AND lower(institution_name)=lower(?) AND status='requested' LIMIT 1`).bind(user.id,name).first();
  if(existing) return json({error:'You already requested this institution.'},409);
  await env.DB.prepare(`INSERT INTO institution_requests(profile_id,institution_name,state,reason) VALUES(?,?,?,?)`).bind(user.id,name,state,reason).run();
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(user.user_id,'institution.request','profile',user.avx_id,JSON.stringify({institution_name:name,state})).run();
  return json({ok:true,message:'Institution request submitted. AVELYX will review it for partnership onboarding.'},201);
}

async function verificationRequestsV2(request, env){
  await ensureInstitutionTables(env);
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const rows=await env.DB.prepare(`SELECT v.id,v.credential_type,v.qualification,v.programme,v.graduation_year,v.reference,v.status,v.avx_cost,v.notes,v.created_at,v.updated_at,i.name institution_name,i.status institution_status FROM verification_submissions v JOIN institutions i ON i.id=v.institution_id WHERE v.profile_id=? ORDER BY v.id DESC`).bind(user.id).all();
  return json({requests:rows.results||[]});
}

async function submitCredentialVerification(request, env){
  await ensureInstitutionTables(env);
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const b=await request.json().catch(()=>({}));
  const institutionId=Number(b.institution_id||0), credentialType=String(b.credential_type||'').trim().toLowerCase();
  const qualification=String(b.qualification||'').trim().slice(0,180), programme=String(b.programme||'').trim().slice(0,180), graduationYear=String(b.graduation_year||'').trim().slice(0,20), reference=String(b.reference||'').trim().slice(0,120);
  const fileName=String(b.file_name||'').trim().slice(0,180), mime=String(b.mime_type||'').trim().toLowerCase(), data=String(b.data_base64||'');
  const allowedTypes=RINGO_ALLOWED_CREDENTIAL_TYPES;
  const allowedMime=RINGO_ALLOWED_MIME;
  if(!institutionId) return json({error:'Select an institution.'},400);
  if(!allowedTypes.includes(credentialType)) return json({error:'Select a valid credential type.'},400);
  if(!qualification) return json({error:'Qualification/title is required.'},400);
  if(!allowedMime.includes(mime)) return json({error:'Upload a PDF, JPG, PNG or WebP document.'},400);
  if(!data || data.length>2800000) return json({error:'Document is missing or too large. Keep the file under about 2 MB for the MVP.'},400);
  const institution=await env.DB.prepare(`SELECT id,name,status,processing_time FROM institutions WHERE id=?`).bind(institutionId).first();
  if(!institution) return json({error:'Institution not found.'},404);
  if(institution.status!=='active') return json({error:'This institution is not currently accepting paid AVELYX verification requests.'},403);
  const pending=await env.DB.prepare(`SELECT id FROM verification_submissions WHERE profile_id=? AND institution_id=? AND status IN ('submitted','under_review','sent_to_institution','awaiting_institution_response') LIMIT 1`).bind(user.id,institutionId).first();
  if(pending) return json({error:'You already have an active verification request with this institution.'},409);
  const cost=await credentialPrice(env,credentialType);
  if(!cost) return json({error:`Pricing for ${credentialType} has not been configured yet. AVELYX will publish the verification price before you can submit this credential.`},409);
  const fresh=await env.DB.prepare(`SELECT avx_balance FROM profiles WHERE id=?`).bind(user.id).first();
  const balance=Number(fresh?.avx_balance||0);
  if(balance<cost) return json({error:`You need ${cost} AVX for this verification. Your current balance is ${balance} AVX.`},402);
  const ref=reference||makeVerificationReference();
  let result;
  try {
    result=await env.DB.prepare(`INSERT INTO verification_submissions(profile_id,user_id,institution_id,credential_type,qualification,programme,graduation_year,reference,file_name,mime_type,data_base64,status,avx_cost) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(user.id,user.user_id,institutionId,credentialType,qualification,programme,graduationYear,ref,fileName,mime,data,'pending_payment',cost).run();
    await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(user.user_id,'verification.submit','verification_submission',String(result.meta?.last_row_id||''),JSON.stringify({institution_id:institutionId,institution:institution.name,cost,reference:ref,status:'pending_payment'})).run();
  } catch(e) {
    return json({error:'Verification could not be recorded. Your AVX was returned.'},500);
  }
  return json({ok:true,request_id:result.meta?.last_row_id||null,reference:ref,cost,status:'submitted',processing_time:institution.processing_time||'Up to 3 working days',message:'Verification submitted. AVELYX will review the document and coordinate with the selected partner institution.'},201);
}

async function adminInstitutions(request, env){
  await ensureInstitutionTables(env); const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const rows=await env.DB.prepare(`SELECT * FROM institutions ORDER BY name`).all(); return json({institutions:rows.results||[]});
}
async function adminSaveInstitution(request, env){
  await ensureInstitutionTables(env); const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json().catch(()=>({})); const name=String(b.name||'').trim().slice(0,180),state=String(b.state||'').trim().slice(0,80),country=String(b.country||'Nigeria').trim().slice(0,80),type=String(b.institution_type||'University').trim().slice(0,80),status=String(b.status||'onboarding').trim(),method=String(b.verification_method||'manual').trim().slice(0,80),processing=String(b.processing_time||'Up to 3 working days').trim().slice(0,80),contactName=String(b.contact_name||'').trim().slice(0,120),contactEmail=String(b.contact_email||'').trim().slice(0,180),contactPhone=String(b.contact_phone||'').trim().slice(0,60),notes=String(b.notes||'').trim().slice(0,500);
  if(!name) return json({error:'Institution name is required.'},400); if(!['active','onboarding','inactive'].includes(status)) return json({error:'Invalid institution status.'},400);
  if(b.id){await env.DB.prepare(`UPDATE institutions SET name=?,state=?,country=?,institution_type=?,status=?,verification_method=?,processing_time=?,contact_name=?,contact_email=?,contact_phone=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(name,state,country,type,status,method,processing,contactName,contactEmail,contactPhone,notes,Number(b.id)).run();}
  else {try{await env.DB.prepare(`INSERT INTO institutions(name,state,country,institution_type,status,verification_method,processing_time,contact_name,contact_email,contact_phone,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(name,state,country,type,status,method,processing,contactName,contactEmail,contactPhone,notes).run();}catch(e){return json({error:'Institution name already exists.'},409)}}
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'institution.save','institution',String(b.id||name),JSON.stringify({name,status})).run();
  return json({ok:true});
}
async function adminVerificationCenter(request, env){
  await ensureInstitutionTables(env); const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const rows=await env.DB.prepare(`SELECT v.*,i.name institution_name,p.full_name,p.avx_id,u.email FROM verification_submissions v JOIN institutions i ON i.id=v.institution_id JOIN profiles p ON p.id=v.profile_id JOIN users u ON u.id=v.user_id ORDER BY v.id DESC`).all(); return json({requests:rows.results||[]});
}
async function adminUpdateVerification(request, env){
  await ensureInstitutionTables(env); const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json().catch(()=>({})); const id=Number(b.id||0),status=String(b.status||'').trim(),notes=String(b.notes||'').trim().slice(0,1000),institutionResponse=String(b.institution_response||'').trim().slice(0,1000);
  const allowed=RINGO_ACTIVE_STATUSES; if(!id||!allowed.includes(status)) return json({error:'Invalid verification update.'},400);
  const current=await env.DB.prepare('SELECT status FROM verification_submissions WHERE id=?').bind(id).first();
  if(!current) return json({error:'Verification request not found.'},404);
  if(!canVerificationTransition(current.status,status)) return json({error:`Cannot move verification from ${current.status} to ${status}.`},409);
  await env.DB.prepare(`UPDATE verification_submissions SET status=?,notes=?,institution_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(status,notes,institutionResponse,id).run();
  await env.DB.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)`).bind(admin.user_id,'verification.update','verification_submission',String(id),JSON.stringify({status})).run();
  return json({ok:true});
}

function verificationPage(){return shell('Verification Center',`<section class="hero"><div class="eyebrow">AVELYX VERIFICATION CENTER</div><h1>Verify your credential.</h1><p class="muted">Select an active AVELYX partner institution, upload your credential and submit it for review. Target processing time: up to 3 working days.</p></section><section class="panel"><div id="notice" class="muted">Loading partner institutions...</div><div id="form" style="display:none"><div class="grid"><div class="wide"><label>Partner institution *</label><select id="institution"></select><small id="institutionInfo" class="muted"></small></div><div><label>Credential type *</label><select id="credential_type"><option>Degree</option><option>Diploma</option><option>Certificate</option><option>Transcript</option><option>Professional Certification</option><option>Training Certificate</option><option>Other</option></select></div><div><label>Qualification / title *</label><input id="qualification" placeholder="e.g. B.Sc. Computer Science"></div><div><label>Programme</label><input id="programme" placeholder="e.g. Computer Science"></div><div><label>Graduation year</label><input id="graduation_year" placeholder="2025"></div><div><label>Reference number</label><input id="reference" placeholder="Certificate / matric / reference number"></div><div class="wide"><label>Credential document *</label><input id="document" type="file" accept=".pdf,.jpg,.jpeg,.png,.webp,application/pdf,image/jpeg,image/png,image/webp"><small class="muted">PDF, JPG, PNG or WebP. MVP limit: about 2 MB.</small></div><div class="wide"><div class="field"><b>Verification fee: <span id="verificationFee">Select a credential type</span></b><br><small class="muted">Pricing is controlled by AVELYX admin. 1 AVX = ₦100. Payment remains pending until admin approval; the AVX is collected only after approval.</small></div></div></div><div class="actions" style="margin-top:16px"><button class="btn" onclick="submitVerification()">Submit Verification</button><a class="btn ghost" href="/wallet.html">View AVX Wallet</a></div><div id="msg"></div></div><div id="requestBox" style="margin-top:18px"><h2>Institution not listed?</h2><p class="muted">Paid verification is only available for active AVELYX partner institutions. You can request that AVELYX consider onboarding your school.</p><div class="grid"><div><label>Institution name</label><input id="requestName"></div><div><label>State</label><input id="requestState" placeholder="State (optional)"></div><div class="wide"><label>Reason (optional)</label><textarea id="requestReason" placeholder="Why should AVELYX add this institution?"></textarea></div></div><button class="btn ghost" onclick="requestSchool()">Request Institution</button><span id="requestMsg"></span></div></section><section class="panel" style="margin-top:16px"><h2>My Verification Requests</h2><div id="requests" class="muted">Loading...</div></section>`,`<script>
let institutions=[];let loadedFile=null;
async function load(){const priceBox=document.getElementById('verificationFee');try{const pr=await fetch('/api/verification/prices');const pd=await pr.json();window.credentialPrices=Object.fromEntries((pd.prices||[]).map(x=>[x.credential_type,x]));updateCredentialPrice();}catch(e){priceBox.textContent='Pricing unavailable';}const r=await fetch('/api/institutions');const d=await r.json();institutions=d.institutions||[];if(institutions.length){form.style.display='block';notice.textContent='Only active partner institutions accept paid verification.';institution.innerHTML=institutions.map(x=>'<option value="'+x.id+'">'+esc(x.name)+' — '+esc(x.state||x.country)+'</option>').join('');updateInstitutionInfo();}else{notice.className='error';notice.textContent='No AVELYX partner institutions are currently available for paid verification.';}loadRequests()}
function updateInstitutionInfo(){const x=institutions.find(i=>String(i.id)===institution.value);institutionInfo.textContent=x?'Status: ACTIVE · '+(x.processing_time||'Up to 3 working days')+' · Method: '+(x.verification_method||'manual'):''} function updateCredentialPrice(){const t=String(credential_type.value||'').toLowerCase();const x=(window.credentialPrices||{})[t];document.getElementById('verificationFee').textContent=(x&&Number(x.active)===1&&Number(x.avx_cost)>0)?Number(x.avx_cost).toLocaleString()+' AVX (₦'+(Number(x.avx_cost)*100).toLocaleString()+')':'Price not set yet'} credential_type?.addEventListener('change',updateCredentialPrice);
institution?.addEventListener('change',updateInstitutionInfo);
document?.getElementById('document')?.addEventListener('change',()=>{loadedFile=document.getElementById('document').files[0]||null});
async function submitVerification(){const msg=document.getElementById('msg');if(!loadedFile){msg.className='error';msg.textContent='Please choose your credential document.';return}if(loadedFile.size>2*1024*1024){msg.className='error';msg.textContent='Keep the document under 2 MB for this MVP.';return}msg.className='muted';msg.textContent='Preparing secure submission...';const reader=new FileReader();reader.onload=async()=>{const data=String(reader.result||'').split(',')[1]||'';const body={institution_id:institution.value,credential_type:credential_type.value.toLowerCase(),qualification:qualification.value,programme:programme.value,graduation_year:graduation_year.value,reference:reference.value,file_name:loadedFile.name,mime_type:loadedFile.type,data_base64:data};const r=await fetch('/api/verification/submit',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));msg.className=r.ok?'toast':'error';msg.textContent=r.ok?'Request created. Reference: '+d.reference+' · '+d.message:d.error||'Unable to submit verification.';if(r.ok){loadedFile=null;document.getElementById('document').value='';loadRequests()}};reader.readAsDataURL(loadedFile)}
async function requestSchool(){const r=await fetch('/api/institution-requests',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({institution_name:requestName.value,state:requestState.value,reason:requestReason.value})});const d=await r.json();requestMsg.className=r.ok?'toast':'error';requestMsg.textContent=d.message||d.error}
async function loadRequests(){const r=await fetch('/api/verification/requests',{credentials:'same-origin'});const d=await r.json();requests.innerHTML=(d.requests||[]).map(x=>'<div class="field"><b>'+esc(x.qualification)+'</b><br><span class="pill">'+esc(String(x.status).replaceAll('_',' ').toUpperCase())+'</span> · '+esc(x.institution_name)+' · '+Number(x.avx_cost||0)+' AVX<br><small class="muted">'+esc(x.credential_type)+' · Submitted '+esc(x.created_at||'')+'</small></div>').join('')||'<p class="muted">No verification requests yet.</p>'}
function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
load();
</script>`)}

function adminInstitutionsPage(){return shell('AVELYX Institution & Verification Control',`<section class="hero"><div class="eyebrow">AVELYX ADMIN</div><h1>Institution & Verification Control</h1><p class="muted">Manage approved partner institutions and review credential verification submissions.</p><div class="actions"><a class="btn ghost" href="/admin.html">Back to Admin</a></div></section><section class="panel"><h2>Partner Institutions</h2><div class="grid"><input id="iid" type="hidden"><div><label>Institution name</label><input id="iname"></div><div><label>State</label><input id="istate" value="Kaduna"></div><div><label>Country</label><input id="icountry" value="Nigeria"></div><div><label>Type</label><input id="itype" value="University"></div><div><label>Status</label><select id="istatus"><option value="active">Active partner</option><option value="onboarding">Onboarding</option><option value="inactive">Inactive / suspended</option></select></div><div><label>Verification method</label><input id="imethod" value="manual"></div><div><label>Processing time</label><input id="iprocess" value="Up to 3 working days"></div><div><label>Contact email</label><input id="iemail"></div><div><label>Contact phone</label><input id="iphone"></div><div class="wide"><label>Notes</label><textarea id="inotes"></textarea></div></div><button class="btn" onclick="saveInstitution()">Save Institution</button><span id="imsg"></span><div id="ilist" style="margin-top:16px"></div></section><section class="panel" style="margin-top:16px"><h2>Verification Requests</h2><div id="vlist">Loading...</div></section>`,`<script>
let instData=[];async function load(){const a=await fetch('/api/admin/institutions');const ad=await a.json();instData=ad.institutions||[];ilist.innerHTML=instData.map(x=>'<div class="field"><b>'+esc(x.name)+'</b> · '+esc(x.state||'')+' · <span class="pill">'+esc(x.status.toUpperCase())+'</span><br><small>'+esc(x.institution_type||'')+' · '+esc(x.verification_method||'manual')+' · '+esc(x.processing_time||'')+'</small><br><button class="btn ghost" onclick="editInst('+x.id+')">Edit</button></div>').join('')||'<p class="muted">No institutions yet.</p>';const r=await fetch('/api/admin/verification');const d=await r.json();vlist.innerHTML=(d.requests||[]).map(x=>'<div class="field"><b>'+esc(x.full_name)+' · '+esc(x.qualification)+'</b><br><small>'+esc(x.avx_id)+' · '+esc(x.institution_name)+' · '+esc(x.email)+'</small><br><span class="pill">'+esc(String(x.status).replaceAll('_',' ').toUpperCase())+'</span><br><select id="st'+x.id+'"><option>submitted</option><option>under_review</option><option>sent_to_institution</option><option>awaiting_institution_response</option><option>verified</option><option>not_verified</option><option>unable_to_verify</option><option>rejected</option></select><input id="nt'+x.id+'" placeholder="Admin note"><input id="ir'+x.id+'" placeholder="Institution response (optional)"><button class="btn ghost" onclick="updateV('+x.id+')">Update</button> <a class="share-url" href="/admin-verification-document.html?id='+x.id+'" target="_blank">Document record</a></div>').join('')||'<p class="muted">No verification submissions.</p>'}
async function saveInstitution(){const b={id:iid.value||null,name:iname.value,state:istate.value,country:icountry.value,institution_type:itype.value,status:istatus.value,verification_method:imethod.value,processing_time:iprocess.value,contact_email:iemail.value,contact_phone:iphone.value,notes:inotes.value};const r=await fetch('/api/admin/institutions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();imsg.className=r.ok?'toast':'error';imsg.textContent=r.ok?'Saved.':d.error||'Unable to save.';if(r.ok){clearForm();load()}}
function editInst(id){const x=instData.find(i=>i.id===id);if(!x)return;iid.value=x.id;iname.value=x.name;istate.value=x.state||'';icountry.value=x.country||'Nigeria';itype.value=x.institution_type||'University';istatus.value=x.status;imethod.value=x.verification_method||'manual';iprocess.value=x.processing_time||'Up to 3 working days';iemail.value=x.contact_email||'';iphone.value=x.contact_phone||'';inotes.value=x.notes||'';window.scrollTo({top:0,behavior:'smooth'})}
function clearForm(){['iid','iname','iemail','iphone','inotes'].forEach(id=>document.getElementById(id).value='');istate.value='Kaduna';icountry.value='Nigeria';itype.value='University';istatus.value='onboarding';imethod.value='manual';iprocess.value='Up to 3 working days'}
async function updateV(id){const r=await fetch('/api/admin/verification',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,status:document.getElementById('st'+id).value,notes:document.getElementById('nt'+id).value,institution_response:document.getElementById('ir'+id).value})});const d=await r.json();if(!r.ok)alert(d.error||'Unable to update');load()}
function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}load();
</script>`) }

function styles() { return `<style>:root{--bg:#050817;--panel:#0c1430;--line:#202b50;--text:#f7f8ff;--muted:#9ca9ca;--purple:#8b4dff;--blue:#159cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#17153c 0,#050817 42%);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}.public{max-width:760px;margin:auto;padding:48px 20px}.brand{font-weight:900;font-size:26px;letter-spacing:.18em;margin-bottom:34px}.brand span{color:var(--blue);font-size:12px;margin-left:8px}.profile-card{background:linear-gradient(145deg,#111a3a,#080d21);border:1px solid var(--line);border-radius:28px;padding:34px;box-shadow:0 24px 70px #0008}.center{text-align:center}.eyebrow{font-size:11px;letter-spacing:.18em;color:#8ea3d8;font-weight:800}h1{font-size:42px;line-height:1.05;margin:14px 0 8px}.sub{color:var(--muted);font-size:17px}.status{display:inline-block;margin:18px 0;padding:8px 12px;border:1px solid #275f49;border-radius:999px;color:#67e0a1;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.status.bad{border-color:#693345;color:#ff879e}.fields{display:grid;gap:10px;margin-top:12px}.field{padding:15px;border:1px solid #1d2748;border-radius:14px;background:#070c1d}.field span{display:block;color:#7785aa;font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:5px}.field strong{font-size:15px;word-break:break-word}.field a{color:#65baff}.idbox{margin-top:18px;padding:18px;border-radius:16px;background:#0a1229;border:1px solid #27365e}.idbox small{display:block;color:#7484a8;font-size:10px;letter-spacing:.14em}.idbox b{display:block;margin-top:5px;letter-spacing:.1em}.notice{color:#ffbd68;font-size:13px}.foot{text-align:center;color:#657294;margin-top:24px;font-size:12px}</style>`; }

const appPages = {
  '/register.html': 'register', '/login.html':'login', '/verify-email.html':'verify', '/dashboard.html':'dashboard',
  '/profile.html':'profile', '/admin-login.html':'admin-login', '/verification.html':'verification', '/qr.html':'qr', '/permissions.html':'permissions', '/notifications.html':'notifications', '/wallet.html':'wallet', '/opportunities.html':'opportunities', '/verification.html':'verification', '/digital-cv.html':'digital-cv'
};
function pageAdSlider(title='AVELYX') {
  const ads = [
    ['/ad-01-general.jpg','AVELYX — Your Identity. Verified. Your Future. Unlocked.'],
    ['/ad-02-wallet.jpg','AVX Wallet — Buy and manage AVX for AVELYX services.'],
    ['/ad-03-profile.jpg','Your AVELYX Profile — Showcase your identity and professional story.'],
    ['/ad-04-credentials.jpg','Credentials — Verified. Trusted. Ready to prove.'],
    ['/ad-05-jobs.jpg','Jobs & Opportunities — Your skills. Real opportunities.']
  ];
  const key=String(title).toLowerCase();
  let order=[0,1,2,3,4];
  if(key.includes('wallet')) order=[1,0,2,3,4];
  else if(key.includes('profile')) order=[2,0,3,1,4];
  else if(key.includes('verification') || key.includes('credential')) order=[3,0,2,1,4];
  else if(key.includes('opportunit') || key.includes('job')) order=[4,0,2,3,1];
  const slides=order.map((idx,pos)=>`<div class="ad-slide" aria-hidden="${pos!==0}"><img src="${ads[idx][0]}" alt="${esc(ads[idx][1])}" loading="${pos===0?'eager':'lazy'}"></div>`).join('');
  const dots=order.map((idx,pos)=>`<button class="ad-dot ${pos===0?'active':''}" aria-label="Advertisement ${pos+1}" onclick="avelyxAdGo(${pos})"></button>`).join('');
  return `<section class="page-ad-slider" aria-label="AVELYX information and advertisements"><div class="ad-track" id="avelyxAdTrack">${slides}</div><button class="ad-arrow ad-prev" aria-label="Previous advertisement" onclick="avelyxAdStep(-1)">‹</button><button class="ad-arrow ad-next" aria-label="Next advertisement" onclick="avelyxAdStep(1)">›</button><div class="ad-dots">${dots}</div></section>`;
}
function adSliderScript(){ return `<script>(function(){let n=0,timer;const total=5;function paint(){const tr=document.getElementById('avelyxAdTrack');if(!tr)return;tr.style.transform='translateX(-'+(n*100)+'%)';document.querySelectorAll('.ad-dot').forEach((d,i)=>d.classList.toggle('active',i===n));document.querySelectorAll('.ad-slide').forEach((s,i)=>s.setAttribute('aria-hidden',i!==n));}window.avelyxAdGo=function(i){n=(i+total)%total;paint();restart()};window.avelyxAdStep=function(d){n=(n+d+total)%total;paint();restart()};function restart(){clearInterval(timer);timer=setInterval(()=>{n=(n+1)%total;paint()},6500)}paint();restart()})();</script>`; }
function shell(title, content, script='') { return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} • AVELYX</title>${styles()}<style>.app{max-width:1180px;margin:auto;padding:16px 16px 60px}.app-nav{position:sticky;top:0;z-index:50;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0 14px;background:linear-gradient(#050817 75%,transparent)}.app-brand{color:#fff;text-decoration:none;font-weight:950;font-size:21px;letter-spacing:.18em}.app-menu-btn{width:46px;height:46px;border:1px solid #28345a;border-radius:15px;background:#0b1228;color:#fff;font-size:24px;cursor:pointer;display:grid;place-items:center}.app-menu{position:absolute;right:0;top:58px;width:min(310px,calc(100vw - 32px));padding:10px;border:1px solid #2b3760;border-radius:20px;background:rgba(8,13,31,.98);box-shadow:0 24px 70px #000b;display:none}.app-menu.open{display:block}.app-menu a{display:flex;align-items:center;gap:12px;padding:12px 13px;border-radius:13px;color:#e9edff;text-decoration:none;font-weight:750}.app-menu a:hover{background:#121b38}.menu-icon{width:30px;height:30px;border-radius:10px;display:grid;place-items:center;background:#141d3c;color:#bda8ff;font-size:15px}.app-menu .menu-divider{height:1px;background:#222d4f;margin:7px 3px}.app-menu .menu-muted{color:#7886aa;font-size:12px;padding:9px 13px}.menu-account{display:flex;align-items:center;gap:10px;padding:10px 10px 13px;margin-bottom:4px;border-bottom:1px solid #202b4c}.menu-account b{display:block;font-size:12px;letter-spacing:.08em}.menu-account small{display:block;color:#7180a3;font-size:10px;margin-top:2px}.page-title{font-size:11px;letter-spacing:.18em;color:#8393c4;font-weight:900;margin:5px 0 0}.btn{border:0;border-radius:12px;padding:13px 18px;font-weight:800;cursor:pointer;color:white;background:linear-gradient(135deg,var(--purple),var(--blue));box-shadow:0 10px 30px #315bff22}.btn.ghost{background:#111a36;border:1px solid var(--line);box-shadow:none}.notify-btn{position:absolute;right:4px;top:4px;width:48px;height:48px;border-radius:16px;border:1px solid var(--line);background:#111a36;color:#fff;font-size:21px;cursor:pointer}.notify-badge{position:absolute;right:-4px;top:-5px;min-width:20px;height:20px;padding:0 5px;border-radius:999px;background:#ff477e;color:#fff;font:800 11px/20px system-ui;justify-content:center;align-items:center}.permission-checks{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}.check{margin:0;padding:10px;border:1px solid var(--line);border-radius:10px;background:#070c1d}.check input{width:auto;margin-right:8px}.permission-card{margin-bottom:10px}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.panel{background:#0b122a;border:1px solid var(--line);border-radius:22px;padding:24px}.panel h2{margin-top:0}.muted{color:var(--muted)}label{display:block;font-size:12px;color:#9aa8c9;margin:13px 0 7px}input,textarea,select{width:100%;padding:13px 14px;border-radius:12px;border:1px solid #263354;background:#070d20;color:white;outline:none}textarea{min-height:100px;resize:vertical}.wide{grid-column:1/-1}.toast{margin-top:12px;color:#7ee8b1}.error{color:#ff91a5;margin-top:12px}.hero{padding:34px 0 22px}.hero h1{font-size:46px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.soon{opacity:.62;position:relative;overflow:hidden}.soon:after{content:'COMING SOON';position:absolute;top:15px;right:-31px;transform:rotate(35deg);background:#1d2850;padding:6px 38px;font-size:9px;letter-spacing:.12em}.card-showcase{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.card-image{width:100%;display:block;border-radius:18px;border:1px solid #29365c;box-shadow:0 20px 50px #0008}.soon-label{display:inline-block;margin:0 0 10px;padding:5px 9px;border-radius:999px;background:#101b3b;color:#a9b9df;font-size:9px;letter-spacing:.14em;font-weight:900}@media(max-width:760px){.card-showcase{grid-template-columns:1fr}}.qrbox{text-align:center}.qrbox canvas,.qrbox img{max-width:260px;margin:16px auto;display:block;background:white;padding:10px;border-radius:14px}.pill{display:inline-block;padding:7px 10px;border-radius:999px;background:#101b3b;color:#9eb1de;font-size:11px}.share-url{word-break:break-all;color:#73bdff;font-size:12px}.actions{display:flex;gap:10px;flex-wrap:wrap}.avx-actions{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:18px}.avx-icon{min-height:74px;border-radius:17px;border:1px solid #202a49;background:#070b16;color:#46506d;font-size:12px;font-weight:900;cursor:not-allowed;box-shadow:none;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:5px}.avx-icon.locked{opacity:.52;filter:grayscale(1)}.avx-icon svg{width:23px;height:23px;display:block}@media(max-width:760px){.grid,.cards{grid-template-columns:1fr}.hero h1{font-size:35px}.avx-actions{grid-template-columns:repeat(2,1fr)}}.app-content{min-height:60vh}.page-ad-slider{position:relative;margin:0 0 22px;border:1px solid rgba(139,77,255,.38);border-radius:24px;overflow:hidden;background:radial-gradient(circle at 50% 0,#17113a,#070914 70%);box-shadow:0 22px 70px #0009}.ad-track{display:flex;transition:transform .55s cubic-bezier(.2,.75,.2,1);will-change:transform}.ad-slide{min-width:100%;display:flex;align-items:center;justify-content:center;background:#05060c}.ad-slide img{display:block;width:100%;height:min(270px,25vw);min-height:170px;object-fit:contain;background:#05060c}.ad-arrow{position:absolute;top:50%;transform:translateY(-50%);width:42px;height:42px;border-radius:50%;border:1px solid rgba(255,255,255,.25);background:rgba(5,6,12,.72);backdrop-filter:blur(8px);color:#fff;font-size:30px;line-height:1;cursor:pointer;z-index:3}.ad-prev{left:12px}.ad-next{right:12px}.ad-dots{position:absolute;bottom:12px;left:0;right:0;display:flex;justify-content:center;gap:7px;z-index:4}.ad-dot{width:8px;height:8px;border:0;border-radius:50%;padding:0;background:#655f77;cursor:pointer}.ad-dot.active{width:22px;border-radius:8px;background:linear-gradient(90deg,var(--purple),#ff3f8e)}.logo-icon{padding:4px!important;overflow:hidden}.logo-icon img{width:100%;height:100%;object-fit:contain;display:block}.ad-slot{display:flex;align-items:center;justify-content:center;min-height:74px;margin:0 0 18px;border:1px dashed #39476f;border-radius:17px;background:linear-gradient(90deg,#090e22,#11162e,#090e22);color:#6f7da4;font-size:10px;letter-spacing:.18em;font-weight:900}.app-footer{margin-top:30px;padding-top:18px;border-top:1px solid #1c2747;color:#657294;font-size:11px;text-align:center}@media(max-width:520px){.app{padding-left:12px;padding-right:12px}.app-menu{right:-1px}.panel{padding:18px}.ad-slide img{height:190px;min-height:0}.ad-arrow{width:36px;height:36px;font-size:26px}.page-ad-slider{border-radius:18px}}</style></head><body><div class="app"><nav class="app-nav"><div><a class="app-brand" href="/dashboard.html">AVELYX</a><div class="page-title">${esc(title)}</div></div><div style="position:relative"><button class="app-menu-btn" aria-label="Open menu" onclick="document.getElementById('appMenu').classList.toggle('open')">☰</button><div id="appMenu" class="app-menu"><div class="menu-account" id="menuAccount"><span class="menu-icon logo-icon"><img src="/avelix-verify-icon.png" alt="AVELYX verification emblem"></span><div><b>AVELYX</b><small>Member workspace</small></div></div><a href="/dashboard.html"><span class="menu-icon">⌂</span><span id="menuDashboard">Dashboard</span></a><a href="/profile.html"><span class="menu-icon">◉</span><span id="menuProfile">My Profile</span></a><a href="/digital-cv.html"><span class="menu-icon">▤</span><span>Digital CV</span></a><a href="/verification.html"><span class="menu-icon">✓</span><span id="menuVerification">Verification Center</span></a><a href="/wallet.html"><span class="menu-icon">◈</span><span id="menuWallet">AVX Wallet</span></a><a href="/opportunities.html"><span class="menu-icon">◆</span><span id="menuOpportunities">Jobs & Opportunities</span></a><a href="/qr.html"><span class="menu-icon">▦</span><span id="menuQr">Secure QR</span></a><a href="/permissions.html"><span class="menu-icon">⌘</span><span id="menuPermissions">Information Permissions</span></a><a href="/notifications.html"><span class="menu-icon">♢</span><span id="menuNotifications">Notifications</span></a><a href="#" onclick="event.preventDefault();alert('AVELYX Search Network is coming soon.');"><span class="menu-icon">⌕</span>Search Network <small style="margin-left:auto;color:#707da1">SOON</small></a><div class="menu-divider"></div><div class="menu-muted" id="menuHint">Identity search • Business search • Individual search</div><a href="/" onclick="return confirm('Leave your AVELYX dashboard?')"><span class="menu-icon">↗</span>Public AVELYX</a><a href="/admin-login.html"><span class="menu-icon">⚙</span>Admin Access</a><a href="#" onclick="event.preventDefault();fetch('/api/logout',{method:'POST'}).then(()=>location.href='/')"><span class="menu-icon">⇥</span>Log out</a></div></div></nav>${pageAdSlider(title)}<main class="app-content">${content}</main><footer class="app-footer">AVELYX • Prove Your Potential</footer></div>${adSliderScript()}${script}<script>document.addEventListener('click',e=>{const m=document.getElementById('appMenu');const b=document.querySelector('.app-menu-btn');if(m&&m.classList.contains('open')&&!m.contains(e.target)&&e.target!==b)m.classList.remove('open')});</script></body></html>`, {headers:{'content-type':'text/html; charset=UTF-8'}}); }

async function dashboardPage(request, env){
  const user=await currentUser(request,env); if(!user) return Response.redirect(new URL('/login.html',request.url),302);
  const settings=await getSettings(env);
  const type=user.account_type||'individual';
  const copy={
    individual:{eyebrow:'AVELYX • PERSONAL IDENTITY',title:'Your professional identity, organized.',desc:'Build one trusted professional identity, prepare credentials for verification and connect your profile to opportunities.'},
    entrepreneur:{eyebrow:'AVELYX • PROFESSIONAL & VENTURE HUB',title:'Your professional and venture hub.',desc:'Bring your professional identity, credentials and opportunity journey together in one AVELYX workspace.'},
    business:{eyebrow:'AVELYX • COMPANY WORKSPACE',title:'Your company workspace.',desc:'Present your business identity, manage credentials, support recruitment and keep your company information organized.'}
  }[type]||{eyebrow:'AVELYX • PROFESSIONAL IDENTITY',title:'Your professional identity, organized.',desc:'Build one trusted professional identity.'};
  let pending=0; try{pending=Number((await env.DB.prepare(`SELECT COUNT(*) n FROM information_requests WHERE profile_id=? AND status='pending'`).bind(user.id).first())?.n||0)}catch(e){}
  let cardNotice='';
  if(settings.cards_enabled==='1'){try{const el=await cardEligibility(user,env); if(el.eligible){const o=await env.DB.prepare(`SELECT id FROM card_orders WHERE user_id=? AND status IN ('pending_payment','approved') LIMIT 1`).bind(user.user_id).first(); if(!o) cardNotice='<div class="notice-card"><span>◈</span><div><b>Your AVELYX Card is ready for approval</b><small>Your profile currently meets the card requirements. Submit your card order when cards are launched.</small></div></div>';}}catch(e){}}
  const identityTier=type==='business'?'Gold Business':type==='entrepreneur'?'Platinum Professional':'Basic Individual';
  const content=`<section class="dash-hero"><div class="dash-copy"><div class="eyebrow">${esc(copy.eyebrow)}</div><h1>${esc(copy.title)}</h1><p>${esc(copy.desc)}</p><div class="dash-actions"><a class="btn" href="/profile.html">Open My Profile</a><a class="btn ghost" href="/qr.html">Share My QR</a></div></div><div class="dash-mark"><img src="/avelix-verify-icon.png" alt="AVELYX verification emblem"><small>AVELYX VERIFIED</small></div></section>
  <section class="dash-grid"><a class="dash-tile featured" href="/profile.html"><span>01</span><b>My Professional Identity</b><small>Keep your profile complete and ready to share.</small></a><a class="dash-tile" href="/digital-cv.html"><span>02</span><b>Digital CV</b><small>Your live professional CV, automatically linked to your AVELYX profile.</small></a><a class="dash-tile" href="/verification.html"><span>02</span><b>Verify Credentials</b><small>Submit supported credentials through the AVELYX verification center.</small></a><a class="dash-tile" href="/wallet.html"><span>03</span><b>AVX Wallet</b><small>View your AVX balance and service-credit activity.</small></a><a class="dash-tile" href="/opportunities.html"><span>04</span><b>Jobs & Opportunities</b><small>Explore professional opportunities matched to your profile.</small></a><a class="dash-tile" href="/permissions.html"><span>05</span><b>Information Permissions</b><small>Control exactly what information you approve for sharing.</small>${pending?`<span class="badge">${pending}</span>`:''}</a><a class="dash-tile" href="/notifications.html"><span>06</span><b>Notifications</b><small>Review important requests and account activity.</small></a></section>
  ${cardNotice}<section class="grid dash-bottom"><div class="panel"><div class="eyebrow">YOUR AVELYX LEVEL</div><h2>${esc(identityTier)}</h2><div class="identity-card"><b>${esc(user.full_name)}</b><br><span class="pill">${esc(user.avx_id)}</span><p class="muted">${esc(user.title||'Professional identity')} ${user.organization?' · '+esc(user.organization):''}</p><small class="muted">Account type: ${esc(type)}</small></div><a class="btn" href="/profile.html" style="display:inline-block;margin-top:14px;text-decoration:none">Manage Profile</a></div><div class="panel"><div class="eyebrow">AVX WALLET</div><h2>${Number(user.avx_balance||0).toLocaleString()} AVX</h2><div class="identity-card"><b>1 AVX = ₦100</b><p class="muted">AVX is an internal AVELYX service credit. Use it for AVELYX services; no P2P transfer, trading or cash-out.</p></div><a class="btn ghost" href="/wallet.html" style="display:inline-block;margin-top:14px;text-decoration:none">Open Wallet</a></div></section><section class="dash-message"><div><div class="eyebrow">THE AVELYX PROMISE</div><h2>Prove Your Potential.</h2><p>Build it. Verify it. Share it. Let your professional identity speak for you.</p></div><a href="/verification.html" class="btn">Build Verification</a></section>`;
  const style=`<style>.dash-hero{display:flex;justify-content:space-between;align-items:center;gap:30px;padding:34px;border-radius:28px;border:1px solid rgba(139,77,255,.3);background:radial-gradient(circle at 82% 25%,rgba(139,77,255,.26),transparent 28%),linear-gradient(135deg,#080d22,#111a3b 60%,#0c1027);box-shadow:0 25px 70px rgba(0,0,0,.22)}.dash-copy{max-width:700px}.dash-copy h1{font-size:clamp(34px,5vw,58px);margin:9px 0 12px;letter-spacing:-1.8px}.dash-copy p{max-width:650px;color:#b9c4e8;line-height:1.7;margin:0}.dash-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}.dash-mark{width:190px;height:190px;flex:0 0 190px;display:grid;place-items:center;position:relative}.dash-mark img{width:150px;height:150px;object-fit:contain;filter:drop-shadow(0 0 30px rgba(139,77,255,.45));}.dash-mark small{position:absolute;bottom:0;font-size:9px;letter-spacing:2px;color:#dce3ff;background:#111936;border:1px solid rgba(255,255,255,.12);padding:7px 10px;border-radius:999px}.dash-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.dash-tile{position:relative;min-height:145px;padding:21px;border:1px solid rgba(105,120,185,.22);border-radius:20px;background:linear-gradient(145deg,#0b122a,#080d20);color:#fff;text-decoration:none;transition:.18s;overflow:hidden}.dash-tile:hover{transform:translateY(-3px);border-color:rgba(139,77,255,.55)}.dash-tile.featured{background:linear-gradient(145deg,rgba(139,77,255,.18),#0b122a 65%);border-color:rgba(139,77,255,.4)}.dash-tile span:first-child{font-size:10px;letter-spacing:1.5px;color:#8d9ac1;font-weight:900}.dash-tile b{display:block;font-size:17px;margin:12px 0 7px}.dash-tile small{display:block;color:#9eabd0;line-height:1.55}.badge{position:absolute;right:14px;top:14px;min-width:24px;height:24px;border-radius:999px;background:#ff477e;text-align:center;line-height:24px;font-size:11px;font-weight:900}.dash-bottom{margin-top:18px}.identity-card{padding:18px;border:1px solid rgba(105,120,185,.24);border-radius:16px;background:linear-gradient(145deg,#080e23,#0c1430)}.notice-card{display:flex;gap:12px;align-items:flex-start;margin-top:18px;padding:16px;border:1px solid rgba(216,184,92,.35);border-radius:18px;background:linear-gradient(110deg,rgba(216,184,92,.10),rgba(139,77,255,.08))}.notice-card>span{font-size:24px;color:#d8b85c}.notice-card b{display:block}.notice-card small{display:block;margin-top:4px;color:#9eabd0}.dash-message{margin-top:18px;padding:24px;border-radius:22px;border:1px solid rgba(212,174,74,.24);background:linear-gradient(110deg,rgba(139,77,255,.12),rgba(212,174,74,.08));display:flex;align-items:center;justify-content:space-between;gap:20px}.dash-message h2{margin:5px 0}.dash-message p{margin:0;color:#aeb9dc}.dash-message .btn{white-space:nowrap}@media(max-width:800px){.dash-hero{flex-direction:column;align-items:flex-start}.dash-mark{align-self:center}.dash-grid{grid-template-columns:1fr 1fr}.dash-message{flex-direction:column;align-items:flex-start}}@media(max-width:520px){.dash-grid{grid-template-columns:1fr}.dash-copy h1{font-size:35px}}</style>`;
  return shell('Dashboard',content,style+memberGuardScript()+`<script>/* Dashboard data is rendered server-side to avoid stuck loading states. */</script>`);
}
async function profilePage(request, env){
  const user=await currentUser(request,env);
  if(!user) return Response.redirect(new URL('/login.html',request.url),302);
  const locked=await profileIsLocked(env,user.id);
  const hasPhoto=!!(await env.DB.prepare('SELECT profile_id FROM profile_photos WHERE profile_id=?').bind(user.id).first());
  const eligibility=await cardEligibility(user,env);
  let credentials=[];
  try { credentials=(await env.DB.prepare("SELECT credential_type,title,status,verified_at,expires_at FROM credentials WHERE profile_id=? ORDER BY created_at DESC").bind(user.id).all()).results||[]; } catch(e) {}
  const tier=eligibility.card_tier||'basic';
  const cardFiles={basic:'/avelix-basic-card.png',platinum:'/avelix-platinum-card.png',gold:'/avelix-gold-card.png'};
  const cardNames={basic:'Basic Card',platinum:'Platinum Card',gold:'Gold Card'};
  const levelNames={individual:'Basic Individual',entrepreneur:'Platinum Professional',business:'Gold Business'};
  const safe=(v)=>esc(v??'');
  const attrSafe=(v)=>esc(v??'');
  const verificationTypes=[['identity','Identity'],['education','Education'],['employment','Employment'],['certification','Certification']];
  if (user.account_type === 'business') verificationTypes.push(['business','Business / CAC']);
  const statusFor=(type)=>{ const c=credentials.find(x=>String(x.credential_type||'').toLowerCase()===type); return c?String(c.status||'pending').toLowerCase():'not submitted'; };
  const verificationCards=verificationTypes.map(([type,label])=>{
    const st=statusFor(type); const cls=st==='verified'?'verified':(st==='pending'?'pending':(st==='rejected'?'rejected':''));
    return `<div class="verify-card"><div class="verify-icon">${type==='identity'?'ID':type==='education'?'ED':type==='employment'?'WK':type==='certification'?'CR':'BC'}</div><div class="verify-main"><b>${label}</b><small>${st==='verified'?'Verified credential recorded':st==='pending'?'Verification is under review':st==='rejected'?'Verification needs attention':'Ready for verification'}</small></div><span class="verify-status ${cls}">${safe(st.toUpperCase())}</span></div>`;
  }).join('');
  const missingHtml=eligibility.missing.length?`<div class="requirements"><b>To unlock your card</b><div>${eligibility.missing.map(x=>`<span>• ${safe(x)}</span>`).join('')}</div></div>`:`<div class="requirements ready"><b>Everything required is complete.</b><span>Your profile is eligible for this card.</span></div>`;
  const journey=(active)=>[['individual','Basic Individual','01'],['entrepreneur','Platinum Professional','02'],['business','Gold Business','03']].map(([k,n,num])=>`<div class="journey-step ${k===active?'active':''}"><span>${num}</span><div><b>${n}</b><small>${k===active?'CURRENT LEVEL':'SELECTED AT REGISTRATION'}</small></div></div>`).join('');
  const content=`<section class="profile-hero-new"><div class="hero-glow purple"></div><div class="hero-glow gold"></div><div class="hero-copy"><div class="eyebrow gold-text">AVELYX • PROFESSIONAL IDENTITY</div><div class="hero-title-row"><div class="avatar-mark">A<span>✓</span></div><div><h1>${safe(user.full_name)}</h1><p>${safe(user.title||'Professional identity')} ${user.organization?`<span>•</span> ${safe(user.organization)}`:''}</p></div></div><div class="hero-tags"><span>AVELYX ID <b>${safe(user.avx_id)}</b></span><span>${safe(levelNames[user.account_type]||'Basic Individual')}</span><span>● ${safe(user.status||'ACTIVE')}</span></div></div><div class="hero-score"><div class="score-ring"><strong>${eligibility.missing.length?Math.max(35,100-Math.min(65,eligibility.missing.length*10)):100}%</strong><small>PROFILE<br>READY</small></div></div></section>

<section class="quick-grid"><div class="quick-card purple-card"><small>IDENTITY</small><strong>${safe(user.avx_id)}</strong><span>Permanent AVELYX ID</span></div><div class="quick-card gold-card"><small>CARD TIER</small><strong>${safe((tier||'basic').toUpperCase())}</strong><span>${eligibility.eligible?'Eligible now':'Verification required'}</span></div><div class="quick-card dark-card"><small>AVX WALLET</small><strong>${Number(user.avx_balance||0).toLocaleString()} AVX</strong><span>Current available balance</span></div></section>

<section class="card-showcase-new"><div class="section-title"><div><div class="eyebrow gold-text">MEMBERSHIP CARD</div><h2>${safe(cardNames[tier]||'AVELYX Card')}</h2><p>Your professional identity, presented with AVELYX premium styling.</p></div><span class="status-chip ${eligibility.eligible?'good':'warn'}">${eligibility.eligible?'ELIGIBLE':'VERIFICATION REQUIRED'}</span></div><div class="card-stage"><div class="card-light"></div><img id="memberCardImage" src="${cardFiles[tier]||cardFiles.basic}" alt="${safe(cardNames[tier]||'AVELYX Card')}"><div class="card-info"><div><small>CARD LEVEL</small><b>${safe((tier||'basic').toUpperCase())}</b></div><div><small>AVELYX ID</small><b>${safe(user.avx_id)}</b></div></div></div>${missingHtml}<div class="card-actions"><button id="purchaseCardBtn" class="btn premium-btn" ${eligibility.eligible?'':'disabled'} onclick="purchaseCard()">${eligibility.eligible?'Purchase '+safe(cardNames[tier]||'Card'):'Complete Verification First'}</button><a class="btn ghost" href="/qr.html">Share Secure QR</a><span id="purchaseMsg" class="muted"></span></div></section>

<section class="panel-new photo-panel"><div class="section-title"><div><div class="eyebrow gold-text">PROFILE PHOTO</div><h2>Your professional photo</h2><p>Upload once for your AVELYX identity. Photo replacement is disabled in the MVP.</p></div><span class="status-chip ${hasPhoto?'good':'warn'}">${hasPhoto?'UPLOADED':'NOT UPLOADED'}</span></div><div class="photo-row"><div class="photo-preview">${hasPhoto?'<img src="/api/profile/photo" alt="Profile photo">':'<span>A</span>'}</div>${hasPhoto?'':`<input id="profilePhoto" type="file" accept="image/jpeg,image/png,image/webp"><button class="btn ghost" onclick="uploadPhoto()">Upload Photo</button>`}</div></section>

<section class="profile-columns"><div class="panel-new details-card"><div class="section-title"><div><div class="eyebrow">YOUR DETAILS</div><h2>Professional Profile</h2><p>Edit your information and keep your identity current.</p></div><span class="live-chip">● LIVE</span></div><form id="profileForm" onsubmit="event.preventDefault();saveProfile()"><fieldset id="profileFields" ${locked?'disabled':''} style="border:0;padding:0;margin:0"><div class="form-grid"><div class="full"><label>AVELYX ID</label><div class="readonly-id">${safe(user.avx_id)} <span>Permanent</span></div></div><div><label>Full name *</label><input id="full_name" value="${attrSafe(user.full_name)}"></div><div><label>Professional title</label><input id="title" value="${attrSafe(user.title)}"></div><div><label>Organization / business</label><input id="organization" value="${attrSafe(user.organization)}"></div><div><label>Industry</label><input id="industry" value="${attrSafe(user.industry)}"></div><div><label>Location</label><input id="location" value="${attrSafe(user.location)}"></div><div><label>Phone</label><input id="phone" value="${attrSafe(user.phone)}"></div><div><label>Website</label><input id="website" value="${attrSafe(user.website)}"></div>${user.account_type==='business'?`<div><label>CAC / RC number</label><input id="cac_number" value="${attrSafe(user.cac_number)}"></div>`:''}<div class="full"><label>Skills</label><input id="skills" value="${attrSafe(user.skills)}" placeholder="Python, CAD, leadership, marketing..."></div><div class="full"><label>Qualifications</label><textarea id="qualifications">${safe(user.qualifications)}</textarea></div><div class="full"><label>Certifications</label><textarea id="certifications">${safe(user.certifications)}</textarea></div><div class="full"><label>About you</label><textarea id="bio">${safe(user.bio)}</textarea></div></div></fieldset><div class="save-row">${locked?'<button class="btn premium-btn" type="button" onclick="editProfile()">Edit Profile</button>':'<button class="btn premium-btn" type="submit">Save Changes</button>'}<span id="msg"></span></div></form></div>
<div class="panel-new level-card"><div class="eyebrow gold-text">AVELYX LEVEL</div><h2>${safe(levelNames[user.account_type]||'Basic Individual')}</h2><p>Your account level controls the membership experience and card tier available to you.</p><div class="journey">${journey(user.account_type||'individual')}</div><div class="upgrade-box" id="upgradeBox"><span class="status-chip good">ACCOUNT LEVEL SELECTED AT REGISTRATION</span></div></div></section>

<section class="panel-new verification-new"><div class="section-title"><div><div class="eyebrow gold-text">VERIFICATION CENTER</div><h2>Build a verified identity</h2><p>Track the credentials connected to your AVELYX profile. Verified credentials help unlock premium features.</p></div><span class="secure-badge">SECURE</span></div><div class="verification-grid-new">${verificationCards}</div><div class="verification-note"><span>✦</span><div><b>Verification is controlled by AVELYX.</b><small>Do not submit passwords or private account credentials. Verification evidence should come from the relevant issuer or authorized source.</small></div></div></section>`;
  const script=`<script>async function saveProfile(){const msg=document.getElementById('msg');const body={full_name:document.getElementById('full_name').value,email:${JSON.stringify(user.login_email||user.email)},title:document.getElementById('title').value,organization:document.getElementById('organization').value,industry:document.getElementById('industry').value,location:document.getElementById('location').value,phone:document.getElementById('phone').value,website:document.getElementById('website').value,cac_number:document.getElementById('cac_number')?document.getElementById('cac_number').value:'',skills:document.getElementById('skills').value,qualifications:document.getElementById('qualifications').value,certifications:document.getElementById('certifications').value,bio:document.getElementById('bio').value};msg.className='muted';msg.textContent='Saving...';try{const r=await fetch('/api/profile',{method:'PUT',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));msg.className=r.ok?'toast':'error';msg.textContent=r.ok?'Profile saved successfully.':'Unable to save: '+(d.error||'Please try again.');if(r.ok){await fetch('/api/profile/lock',{method:'POST',credentials:'same-origin'});setTimeout(()=>location.reload(),450)}}catch(e){msg.className='error';msg.textContent='Connection error. Please try again.'}}async function upgrade(target){let body={target_type:target};if(target==='business'){body.organization=prompt('Business / organization name:',${JSON.stringify(user.organization||'')})||'';if(!body.organization)return;body.industry=prompt('Industry:',${JSON.stringify(user.industry||'')})||'';body.cac_number=prompt('CAC / RC number (optional):',${JSON.stringify(user.cac_number||'')})||''}const r=await fetch('/api/profile/upgrade',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));if(!r.ok){alert(d.error||'Unable to upgrade');return}location.reload()}async function purchaseCard(){const btn=document.getElementById('purchaseCardBtn'),msg=document.getElementById('purchaseMsg');if(btn.disabled)return;btn.disabled=true;msg.textContent='Creating your card order...';try{const r=await fetch('/api/card/purchase',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:'{}'});const d=await r.json().catch(()=>({}));if(r.ok){msg.className='toast';msg.textContent='Order created. Reference: '+d.reference;btn.textContent='Order Created'}else{msg.className='error';msg.textContent=d.error||'Unable to create card order.';btn.disabled=false}}catch(e){msg.className='error';msg.textContent='Connection error. Please try again.';btn.disabled=false}}async function editProfile(){const r=await fetch('/api/profile/unlock',{method:'POST',credentials:'same-origin'});if(r.ok)location.reload();else alert('Unable to unlock profile.')}async function uploadPhoto(){const f=document.getElementById('profilePhoto')?.files?.[0];if(!f)return alert('Choose a photo first.');if(f.size>500*1024)return alert('Keep the photo under 500 KB.');const reader=new FileReader();reader.onload=async()=>{const data=String(reader.result||'').split(',')[1]||'';const r=await fetch('/api/profile/photo',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({mime_type:f.type,data_base64:data})});const d=await r.json().catch(()=>({}));if(!r.ok)return alert(d.error||'Unable to upload photo.');location.reload()};reader.readAsDataURL(f)}</script>`;
  const style=`<style>
.photo-panel{margin-top:16px}.photo-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:12px}.photo-preview{width:96px;height:96px;border-radius:24px;overflow:hidden;border:1px solid rgba(216,184,92,.35);display:grid;place-items:center;background:linear-gradient(145deg,#241b3b,#0b0d18);font-size:38px;font-weight:1000;color:#e3cf88}.photo-preview img{width:100%;height:100%;object-fit:cover}.profile-hero-new{position:relative;overflow:hidden;min-height:285px;padding:34px;border-radius:30px;border:1px solid rgba(194,164,76,.25);background:radial-gradient(circle at 78% 25%,rgba(126,74,255,.35),transparent 28%),radial-gradient(circle at 90% 80%,rgba(212,174,74,.18),transparent 25%),linear-gradient(135deg,#070914,#17112d 52%,#0d0b19);display:flex;align-items:center;justify-content:space-between;gap:28px;box-shadow:0 30px 80px rgba(0,0,0,.3)}.hero-glow{position:absolute;border-radius:50%;filter:blur(30px);pointer-events:none}.hero-glow.purple{width:190px;height:190px;right:120px;top:-90px;background:rgba(135,79,255,.18)}.hero-glow.gold{width:150px;height:150px;right:-50px;bottom:-80px;background:rgba(218,177,68,.14)}.hero-copy{position:relative;z-index:2}.gold-text{color:#d8b85c}.hero-title-row{display:flex;align-items:center;gap:18px;margin-top:8px}.hero-title-row h1{font-size:clamp(34px,6vw,58px);margin:0;letter-spacing:-2px}.hero-title-row p{margin:7px 0 0;color:#bfc5dc}.hero-title-row p span{margin:0 7px;color:#d2b65d}.avatar-mark{width:78px;height:78px;flex:0 0 78px;border-radius:24px;display:grid;place-items:center;background:linear-gradient(145deg,#fff,#d4c7ff 48%,#a982ff);color:#17112b;font-size:44px;font-weight:1000;font-style:italic;box-shadow:0 0 40px rgba(151,104,255,.35);position:relative}.avatar-mark span{position:absolute;right:-6px;bottom:-6px;width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:#17122a;color:#fff;border:3px solid #d6c5ff;font-size:15px;font-style:normal}.hero-tags{display:flex;flex-wrap:wrap;gap:9px;margin-top:20px}.hero-tags span{padding:9px 12px;border-radius:999px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.045);font-size:10px;color:#b9c1dc;letter-spacing:.03em}.hero-tags b{color:#f3e5b3}.hero-score{position:relative;z-index:2}.score-ring{width:145px;height:145px;border-radius:50%;display:grid;place-items:center;align-content:center;text-align:center;border:1px solid rgba(216,184,92,.45);background:radial-gradient(circle,#241d3e,#0b0b16 65%);box-shadow:inset 0 0 35px rgba(145,91,255,.12),0 0 45px rgba(210,173,74,.1)}.score-ring strong{font-size:31px;color:#f0dc9a}.score-ring small{font-size:8px;letter-spacing:1.8px;color:#a8aec6;margin-top:4px}.quick-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:16px}.quick-card{padding:20px;border-radius:20px;border:1px solid rgba(255,255,255,.08);background:#0b0e1b;box-shadow:0 15px 40px rgba(0,0,0,.16)}.quick-card.purple-card{background:linear-gradient(135deg,#15102c,#0b0e1b);border-color:rgba(141,92,255,.28)}.quick-card.gold-card{background:linear-gradient(135deg,#211a0e,#0b0e1b);border-color:rgba(216,184,92,.28)}.quick-card small,.card-info small{display:block;color:#7e87a5;font-size:9px;letter-spacing:1.5px;font-weight:900}.quick-card strong{display:block;font-size:20px;margin:7px 0 3px;color:#f2f4ff}.quick-card span{font-size:11px;color:#929bb8}.card-showcase-new,.panel-new{margin-top:16px;padding:25px;border-radius:24px;border:1px solid rgba(103,119,184,.22);background:linear-gradient(145deg,#0a0d1b,#0e1225);box-shadow:0 18px 50px rgba(0,0,0,.16)}.section-title{display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.section-title h2{margin:4px 0 6px}.section-title p{margin:0;color:#8f98b7;line-height:1.5;font-size:13px}.status-chip,.secure-badge,.live-chip{display:inline-flex;align-items:center;padding:8px 11px;border-radius:999px;font-size:9px;font-weight:1000;letter-spacing:1px;white-space:nowrap}.status-chip.good{color:#80e4ad;background:#0e2a20;border:1px solid #245c42}.status-chip.warn{color:#f3c76b;background:#2b210e;border:1px solid #654d1d}.secure-badge{color:#d9c16e;background:#211b0d;border:1px solid rgba(216,184,92,.3)}.live-chip{color:#83e7b0;background:#0d251c}.card-stage{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:25px 10px 8px;margin-top:8px;overflow:hidden}.card-light{position:absolute;width:500px;height:180px;border-radius:50%;background:radial-gradient(ellipse,rgba(140,86,255,.2),transparent 65%);filter:blur(8px)}.card-stage img{position:relative;width:min(100%,560px);max-height:330px;height:auto;object-fit:contain;border-radius:18px;box-shadow:0 25px 70px rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1)}.card-info{position:relative;width:min(100%,560px);display:flex;justify-content:space-between;gap:15px;margin-top:12px;padding:12px 2px}.card-info b{display:block;margin-top:4px;color:#e9ddbb;font-size:12px}.requirements{margin:8px 0 16px;padding:13px 15px;border-radius:15px;border:1px solid rgba(216,184,92,.16);background:rgba(216,184,92,.045);display:flex;flex-direction:column;gap:7px;color:#c9cfe4;font-size:12px}.requirements b{color:#e3cb82}.requirements div{display:flex;flex-wrap:wrap;gap:6px 16px}.requirements.ready{border-color:rgba(94,210,145,.18);background:rgba(94,210,145,.04)}.requirements.ready b{color:#81e3aa}.card-actions{display:flex;align-items:center;flex-wrap:wrap;gap:10px}.premium-btn{background:linear-gradient(135deg,#7951dc,#a579ff 55%,#d4ad4e);box-shadow:0 12px 35px rgba(122,82,220,.2)}.premium-btn:disabled{opacity:.5;cursor:not-allowed}.profile-columns{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(270px,.75fr);gap:16px}.details-card,.level-card{margin-top:16px}.live-chip{margin-top:2px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 14px;margin-top:16px}.form-grid .full{grid-column:1/-1}.form-grid label{margin-top:12px}.readonly-id{padding:13px 14px;border:1px solid #263354;border-radius:12px;background:#080b17;color:#ddd6f3;font-weight:800}.readonly-id span{float:right;font-size:9px;color:#d7b85e;padding:4px 7px;border-radius:999px;background:#211b0d}.save-row{display:flex;align-items:center;gap:12px;margin-top:16px}.level-card{background:radial-gradient(circle at 80% 15%,rgba(123,76,255,.15),transparent 32%),linear-gradient(160deg,#0e0d20,#0a0d1b)}.level-card>p{color:#8f98b7;line-height:1.55;font-size:13px}.journey{margin-top:20px;border-left:1px solid rgba(216,184,92,.2);padding-left:12px}.journey-step{display:flex;gap:11px;align-items:center;padding:10px 0;color:#6f7895}.journey-step>span{width:27px;height:27px;border-radius:50%;display:grid;place-items:center;border:1px solid rgba(255,255,255,.1);font-size:9px}.journey-step b{display:block;font-size:12px}.journey-step small{font-size:8px;letter-spacing:1px}.journey-step.active{color:#f0f1ff}.journey-step.active>span{background:linear-gradient(135deg,#7b51dd,#c7a54f);color:white;border:0;box-shadow:0 0 20px rgba(145,95,240,.3)}.journey-step.active small{color:#d9bc62}.upgrade-box{margin-top:18px}.verification-new{margin-bottom:18px}.verification-grid-new{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:18px}.verify-card{display:flex;align-items:center;gap:11px;padding:15px;border-radius:17px;border:1px solid rgba(105,120,185,.2);background:linear-gradient(145deg,#0c1020,#090c18)}.verify-icon{width:40px;height:40px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(145deg,#6e48d6,#c3a44e);font-size:9px;font-weight:1000;color:white}.verify-main{min-width:0;flex:1}.verify-main b{display:block;font-size:13px}.verify-main small{display:block;margin-top:4px;color:#818aa7;font-size:10px}.verify-status{padding:6px 8px;border-radius:999px;font-size:8px;font-weight:1000;background:#151a2e;color:#a8b0c9}.verify-status.verified{color:#80e4ad;background:#0d2a20}.verify-status.pending{color:#f4c76c;background:#2b210e}.verify-status.rejected{color:#ff91a5;background:#2b1019}.verification-note{display:flex;gap:11px;align-items:flex-start;margin-top:13px;padding:13px;border-radius:14px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07)}.verification-note>span{color:#d8b85c}.verification-note b{display:block;font-size:11px}.verification-note small{display:block;margin-top:4px;color:#7f89a6;font-size:10px;line-height:1.5}@media(max-width:800px){.profile-hero-new{padding:24px;flex-direction:column;align-items:flex-start}.hero-score{align-self:center}.quick-grid{grid-template-columns:1fr}.profile-columns{grid-template-columns:1fr}.verification-grid-new{grid-template-columns:1fr}.section-title{flex-direction:column}.card-stage img{width:100%;max-width:420px;max-height:250px}.form-grid{grid-template-columns:1fr}.form-grid .full{grid-column:auto}.hero-title-row h1{font-size:35px}.avatar-mark{width:64px;height:64px;flex-basis:64px;font-size:36px}.hero-title-row{align-items:flex-start}.card-actions{align-items:stretch}.card-actions .btn{width:100%;text-align:center}.save-row{flex-direction:column;align-items:flex-start}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style>`;
  return shell('My Profile',content,style+script);
}
function memberGuardScript(){return `<script>async function me(){const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});if(!r.ok){location.href='/login.html';return null}const d=await r.json();return d.profile}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/'}function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}</script>`}
function qrPage(){return shell('Secure QR',`<section class="hero"><div class="eyebrow">SECURE SHARING</div><h1>One-scan AVELYX QR</h1><p class="muted">Generate a temporary link that expires after 30 minutes or one successful scan.</p></section><section class="panel center"><div id="qr" class="qr"></div><div id="qrmsg" class="muted">Tap the button to generate your secure QR.</div><button class="btn" style="margin-top:16px" onclick="generateQR()">Generate Secure QR</button><a class="btn ghost" href="/dashboard.html" style="display:inline-block;margin-top:10px;text-decoration:none">Back to Dashboard</a></section>`,`<style>.center{text-align:center}.qr{min-height:20px}.qr canvas,.qr img{max-width:280px;margin:18px auto;display:block;background:white;padding:10px;border-radius:16px}</style>`+memberGuardScript()+`<script>let qrReady=false;async function loadQrLib(){if(typeof QRCode!=='undefined')return true;return new Promise(resolve=>{const s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';s.onload=()=>resolve(true);s.onerror=()=>resolve(false);document.head.appendChild(s)})}async function generateQR(){const p=await me();if(!p)return;const r=await fetch('/api/share',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({fields:['full_name','title','organization','industry','location','website','bio']})});const d=await r.json();if(!r.ok){qrmsg.className='error';qrmsg.textContent=d.error||'QR generation failed.';return}qr.innerHTML='';const loaded=await loadQrLib();if(loaded){new QRCode(qr,{text:d.url,width:240,height:240});}else{const img=document.createElement('img');img.alt='Secure AVELYX QR';img.src='https://api.qrserver.com/v1/create-qr-code/?size=240x240&data='+encodeURIComponent(d.url);qr.appendChild(img)}qrmsg.innerHTML='<b>ONE SCAN ONLY</b><br>Expires: '+new Date(d.expires_at*1000).toLocaleString()+'<br><span class="share-url">'+esc(d.url)+'</span>'}</script>`)}
function permissionsPage(){return shell('Information Permissions',`<section class="hero"><div class="eyebrow">CONSENT & PRIVACY</div><h1>Information Permissions</h1><p class="muted">Choose exactly what another AVELYX member may access. Nothing is approved automatically.</p></section><section class="grid"><div class="panel"><h2>Requests Received</h2><div id="received">Loading...</div></div><div class="panel"><h2>Request Information</h2><p class="muted">Enter an AVELYX ID and select only the information you need.</p><input id="avxId" placeholder="AVELYX ID"><div id="checks" class="checks">${['full_name','title','organization','industry','location','website','bio','phone','skills','qualifications','certifications','cac_number'].map(f=>`<label class="check"><input type="checkbox" value="${f}"> ${PERMISSION_LABELS[f]||f}</label>`).join('')}</div><textarea id="reason" placeholder="Reason for requesting this information"></textarea><button class="btn" style="margin-top:12px" onclick="requestInfo()">Send Request</button><div id="sentMsg"></div></div></section>`,`<style>.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.check{margin:0;padding:10px;border:1px solid var(--line);border-radius:10px;background:#070c1d}.check input{width:auto;margin-right:7px}.request{margin-bottom:10px}.actions{display:flex;gap:8px;flex-wrap:wrap}@media(max-width:650px){.checks{grid-template-columns:1fr}}</style>`+memberGuardScript()+`<script>const PL={full_name:'Full name',title:'Professional title',organization:'Organization',industry:'Industry',location:'Location',website:'Website',bio:'About',phone:'Phone',skills:'Skills',qualifications:'Qualifications',certifications:'Certifications',cac_number:'CAC / RC number'};function fields(a){return (a||[]).map(x=>'<span class="pill" style="margin:2px">'+esc(PL[x]||x)+'</span>').join('')}async function loadRequests(){const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();if(!r.ok){received.innerHTML='<p class="error">'+esc(d.error||'Unable to load requests')+'</p>';return}received.innerHTML=(d.requests||[]).map(x=>'<div class="field request"><b>'+esc(x.requester_name||'AVELYX member')+'</b><br><small>'+esc(x.requester_email||'')+'</small><p>'+fields(x.requested_fields)+'</p><small class="muted">'+esc(x.reason||'No reason provided')+'</small><br><span class="pill">'+esc(String(x.status).toUpperCase())+'</span>'+(x.status==='pending'?'<div class="actions" style="margin-top:10px"><button class="btn" onclick="respond('+x.id+',true)">Accept</button><button class="btn ghost" onclick="respond('+x.id+',false)">Decline</button></div>':'')+'</div>').join('')||'<p class="muted">No requests yet.</p>'}async function respond(id,yes){let approved=[];if(yes){const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();const row=(d.requests||[]).find(x=>x.id===id);approved=(row?.requested_fields||[]).filter(f=>confirm('Approve access to '+(PL[f]||f)+'?'));if(!approved.length)return alert('No information was approved.')}const r=await fetch('/api/information-requests/'+id+'/respond',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decision:yes?'accepted':'declined',approved_fields:approved})});const d=await r.json();if(!r.ok)return alert(d.error||'Unable to respond');loadRequests()}async function requestInfo(){const id=avxId.value.trim();const fs=[...document.querySelectorAll('#checks input:checked')].map(x=>x.value);if(!id||!fs.length){sentMsg.className='error';sentMsg.textContent='Enter an AVELYX ID and select at least one field.';return}const r=await fetch('/api/information-requests',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({avx_id:id,requested_fields:fs,reason:reason.value.trim()})});const d=await r.json();sentMsg.className=r.ok?'toast':'error';sentMsg.textContent=d.message||d.error;if(r.ok){avxId.value='';reason.value='';document.querySelectorAll('#checks input').forEach(x=>x.checked=false)}}(async()=>{if(await me())loadRequests()})()</script>`)}
function notificationsPage(){return shell('Notifications',`<section class="hero"><div class="eyebrow">NOTIFICATIONS</div><h1>Your Notifications</h1><p class="muted">Important account activity appears here. Permission requests can be reviewed from the Information Permissions page.</p></section><section class="panel"><div id="noticeList">Loading...</div><a class="btn" href="/permissions.html" style="display:inline-block;margin-top:14px;text-decoration:none">Open Information Permissions</a></section>`,`<style>.notice{display:flex;gap:14px;align-items:flex-start;padding:16px;border:1px solid var(--line);border-radius:16px;background:#070c1d;margin-bottom:10px}.notice-icon{font-size:22px}</style>`+memberGuardScript()+`<script>(async()=>{const p=await me();if(!p)return;const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();const pending=(d.requests||[]).filter(x=>x.status==='pending');noticeList.innerHTML=pending.map(x=>'<div class="notice"><div class="notice-icon">🔔</div><div><b>Information request from '+esc(x.requester_name||'AVELYX member')+'</b><p class="muted">They are requesting selected information from your profile.</p><span class="pill">ACTION REQUIRED</span></div></div>').join('')||'<div class="field"><b>No new notifications</b><p class="muted">You are all caught up.</p></div>'})()</script>`)}

async function avxHistory(request, env){
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const rows=await env.DB.prepare('SELECT type,amount,reference,note,created_at FROM avx_transactions WHERE profile_id=? ORDER BY id DESC LIMIT 100').bind(user.id).all();
  return json({transactions:rows.results||[]});
}
function walletPage(){return shell('AVX Wallet',`<section class="hero wallet-hero"><div class="eyebrow">AVX WALLET</div><h1>Your AVX Wallet</h1><p class="muted">AVX is an internal AVELYX service-credit system. Use AVX for AVELYX services. There is no member-to-member transfer, trading or cash-out.</p></section><section class="wallet-top"><div class="wallet-balance"><div class="eyebrow">AVAILABLE AVX</div><div id="balance" class="balance-number">0</div><span>Service credits</span></div><div class="wallet-buy"><div><div class="eyebrow">BUY AVX</div><h2>Top up your service credits</h2><p class="muted">Available packages are shown below when enabled by AVELYX.</p></div><button class="btn premium-btn" onclick="document.getElementById('packages').scrollIntoView({behavior:'smooth'})">View Packages</button></div></section><section class="panel" id="packages"><div class="section-title-lite"><div><div class="eyebrow">AVX PACKAGES</div><h2>Available packages</h2></div><span class="status-chip good">BUY ONLY</span></div><div id="packageList" class="package-grid"><div class="field"><span class="muted">Loading packages…</span></div></div><div id="buyMsg" class="muted" style="margin-top:12px">Payment activation can be connected to the approved AVELYX payment channel. Admin wallet credits remain available for controlled testing.</div></section><section class="panel" style="margin-top:16px"><div class="section-title-lite"><div><div class="eyebrow">ACTIVITY</div><h2>AVX Activity</h2></div></div><div id="history"><div class="field"><span class="muted">Your AVX activity will appear here.</span></div></div></section>`,`<style>.wallet-top{display:grid;grid-template-columns:.75fr 1.25fr;gap:12px;margin-bottom:14px}.wallet-balance,.wallet-buy{padding:22px;border:1px solid #2a3560;border-radius:22px;background:linear-gradient(145deg,#10173a,#080d20);box-shadow:0 18px 55px #0006}.balance-number{font-size:48px;font-weight:950;line-height:1;margin:12px 0 5px;background:linear-gradient(90deg,#fff,#bfa8ff,#d8b85c);-webkit-background-clip:text;background-clip:text;color:transparent}.wallet-balance>span{color:#7e8bad;font-size:11px}.wallet-buy{display:flex;align-items:center;justify-content:space-between;gap:16px}.wallet-buy h2{margin:5px 0}.section-title-lite{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.package-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.package-card{padding:16px;border-radius:18px;border:1px solid #2b3760;background:radial-gradient(circle at 100% 0,#211849,#0a1025 58%)}.package-card b{display:block;font-size:17px}.package-card .amount{font-size:28px;font-weight:950;margin:8px 0}.package-card small{color:#8795b7;line-height:1.45}.package-card button{margin-top:12px;width:100%}.tx{padding:13px;border:1px solid var(--line);border-radius:14px;background:#070c1d;margin:8px 0;display:flex;justify-content:space-between;gap:12px}.tx .amt{font-weight:900}.tx .neg{color:#ff91a5}.tx .pos{color:#7ee8b1}@media(max-width:760px){.wallet-top{grid-template-columns:1fr}.wallet-buy{display:block}.wallet-buy .btn{margin-top:12px}.package-grid{grid-template-columns:1fr}.tx{display:block}}</style>`+memberGuardScript()+`<script>(async()=>{const p=await me();if(!p)return;document.getElementById('balance').textContent=Number(p.avx_balance||0).toLocaleString();try{const pr=await fetch('/api/platform',{credentials:'same-origin',cache:'no-store'});const pd=await pr.json();const list=document.getElementById('packageList');const pkgs=pd.packages||[];list.innerHTML=pkgs.map(x=>'<article class="package-card"><b>'+esc(x.name)+'</b><div class="amount">'+Number(x.avx_amount||0).toLocaleString()+' AVX</div><small>₦'+Number(x.price_ngn||0).toLocaleString()+' · '+esc(x.description||'AVX service credits')+'</small><button class="btn" onclick="requestBuy('+x.id+')">Buy AVX</button></article>').join('')||'<div class="field"><b>No packages are active yet.</b><p class="muted">AVELYX will publish packages here when the buy channel is enabled.</p></div>'}catch(e){document.getElementById('packageList').innerHTML='<div class="field"><b>Packages unavailable</b><p class="muted">Your wallet and balance remain available.</p></div>'}try{const r=await fetch('/api/avx/history',{credentials:'same-origin'});const d=await r.json();document.getElementById('history').innerHTML=(d.transactions||[]).map(x=>'<div class="tx"><div><b>'+esc(x.type||'AVX activity')+'</b><br><small class="muted">'+esc(x.reference||'')+' · '+esc(x.created_at||'')+'</small><br><small class="muted">'+esc(x.note||'')+'</small></div><div class="amt '+(Number(x.amount)<0?'neg':'pos')+'">'+(Number(x.amount)>0?'+':'')+Number(x.amount||0).toLocaleString()+' AVX</div></div>').join('')||'<p class="muted">No AVX transactions yet.</p>'}catch(e){document.getElementById('history').innerHTML='<p class="error">Could not load AVX activity.</p>'}})();function requestBuy(id){document.getElementById('buyMsg').className='toast';document.getElementById('buyMsg').textContent='Package selected. Payment processing will be enabled when the approved AVELYX payment channel is connected.'}</script>`)}
function opportunitiesPage(){return shell('Opportunities',`<section class="hero"><div class="eyebrow">OPPORTUNITIES</div><h1>Find Opportunities</h1><p class="muted">Search jobs using the skills, qualifications and certifications on your AVELYX profile.</p></section><section class="panel"><label>What opportunity are you looking for?</label><input id="q" placeholder="e.g. software developer, mechanical technician"><button class="btn" style="margin-top:12px" onclick="searchJobs()">Search</button><div id="results" style="margin-top:18px"></div></section>`,`<style>.result{margin-bottom:10px}</style>`+memberGuardScript()+`<script>async function searchJobs(){const r=await fetch('/api/jobs/recommendations?q='+encodeURIComponent(q.value));const d=await r.json();if(!r.ok){results.innerHTML='<p class="error">'+esc(d.error||'Unable to search')+'</p>';return}results.innerHTML=(d.jobs||[]).map(j=>'<div class="field result"><b>'+esc(j.title)+'</b><br><span class="muted">'+esc(j.employer)+' · '+esc(j.location||'')+'</span><br><span class="pill">'+esc(j.match_reason||'MATCH')+'</span></div>').join('')||'<p class="muted">No strong matches yet. Add more profile evidence.</p>'}(async()=>{await me()})()</script>`)}

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
  await ensureAdminControlTables(env);
  const treasury=await env.DB.prepare('SELECT * FROM avx_treasury WHERE id=1').first();
  const adminWallet=await env.DB.prepare('SELECT * FROM admin_wallet WHERE id=1').first();
  const prices=await env.DB.prepare('SELECT credential_type,avx_cost,active,updated_at FROM credential_pricing ORDER BY id').all();
  const agents=await env.DB.prepare('SELECT * FROM agents ORDER BY created_at DESC').all();
  const cardOrders=await env.DB.prepare(`SELECT c.*,p.full_name,p.avx_id,p.account_type FROM card_orders c JOIN profiles p ON p.id=c.profile_id ORDER BY c.id DESC LIMIT 100`).all();
  const verificationPayments=await env.DB.prepare(`SELECT v.id,v.reference,v.credential_type,v.qualification,v.avx_cost,v.status,v.created_at,p.full_name,p.avx_id,p.avx_balance,i.name institution_name FROM verification_submissions v JOIN profiles p ON p.id=v.profile_id JOIN institutions i ON i.id=v.institution_id WHERE v.status='pending_payment' ORDER BY v.id DESC`).all();
  return json({settings,packages:packages.results||[],profiles:profiles.results||[],transactions:transactions.results||[],jobs:jobs.results||[],treasury:treasury||null,admin_wallet:adminWallet||null,credential_prices:prices.results||[],agents:agents.results||[],card_orders:cardOrders.results||[],verification_payments:verificationPayments.results||[]});
}
async function adminSetSetting(request, env) {
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const key=String(b.key||'').trim(); const allowed=['avx_enabled','global_search_enabled','verified_credentials_enabled','verify_mark_enabled','cards_enabled','job_search_enabled','verification_cost_avx'];
  if(!allowed.includes(key)) return json({error:'Invalid platform setting.'},400);
  const value=key==='verification_cost_avx' ? String(Math.max(1,Math.min(100000,Math.floor(Number(b.value)||RINGO_DEFAULT_COST)))) : (b.value ? '1' : '0');
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
  if(!avx||amount<=0) return json({error:'Valid AVELYX ID and positive AVX amount are required.'},400);
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

async function ensureDigitalCVTable(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS digital_cv_data (
    profile_id INTEGER PRIMARY KEY,
    soft_skills TEXT,
    hard_skills TEXT,
    education TEXT,
    nysc TEXT,
    awards TEXT,
    work_experience TEXT,
    professional_certifications TEXT,
    summary TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
  )`).run();
}
function cvText(v){ return String(v||'').trim(); }
function cvLines(v){ return cvText(v).split(/\r?\n|\s*;\s*/).map(x=>x.trim()).filter(Boolean); }
function cvList(title, value, cls=''){ const items=cvLines(value); if(!items.length)return ''; return `<section class="cv-section ${cls}"><div class="cv-section-title">${esc(title)}</div><div class="cv-list">${items.map(x=>`<div class="cv-item">${esc(x)}</div>`).join('')}</div></section>`; }
async function getDigitalCV(request, env, publicAvxId=null){
  await ensureDigitalCVTable(env);
  let profile=null;
  if(publicAvxId){ profile=await env.DB.prepare('SELECT * FROM profiles WHERE avx_id=?').bind(String(publicAvxId).toUpperCase()).first(); }
  else { profile=await currentUser(request,env); }
  if(!profile) return null;
  const extra=await env.DB.prepare('SELECT * FROM digital_cv_data WHERE profile_id=?').bind(profile.id).first();
  const credentials=(await env.DB.prepare(`SELECT credential_id,credential_type,title,issuer,reference,status,verified_at,expires_at,notes,created_at FROM credentials WHERE profile_id=? ORDER BY created_at DESC`).bind(profile.id).all()).results||[];
  return {profile,extra:extra||{},credentials};
}
function digitalCVMarkup(data, publicMode=false){
  const p=data.profile||{}, x=data.extra||{};
  const verified=(data.credentials||[]).filter(c=>String(c.status||'').toLowerCase()==='verified');
  const photo=publicMode ? '' : '<img class="cv-avatar" src="/api/profile/photo" alt="Profile photo" onerror="this.style.display=\'none\'">';
  const contact=publicMode ? '' : `<div class="cv-contact"><span>${esc(p.email||'')}</span>${p.phone?`<span>${esc(p.phone)}</span>`:''}</div>`;
  const credHtml=verified.length?`<section class="cv-section"><div class="cv-section-title">Professional Certifications</div><div class="cv-list">${verified.map(c=>`<div class="cv-item"><b>${esc(c.title||c.credential_type)}</b><small>${esc(c.issuer||'Verified issuer')} ${c.verified_at?`• Verified ${esc(String(c.verified_at))}`:''}</small></div>`).join('')}</div></section>`:'';
  return `<div class="cv-wrap"><div class="cv-top"><div class="cv-brand">AVELYX</div><div class="cv-emblem">A<span>✓</span></div></div><div class="cv-hero">${photo}<div class="cv-identity"><div class="cv-kicker">VERIFIED DIGITAL CV</div><h1>${esc(p.full_name||'AVELYX Member')}</h1><div class="cv-title">${esc(p.title||'Professional')}</div><div class="cv-id">${esc(p.avx_id||'')}</div><div class="cv-motto">Prove Your Potential.</div>${contact}<div class="cv-location">${esc(p.location||'')}</div><span class="cv-badge">${String(p.status||'active').toLowerCase()==='active'?'● AVELYX ID ACTIVE':'● AVELYX ID'}</span></div></div>
  ${p.bio||x.summary?`<section class="cv-section"><div class="cv-section-title">Professional Summary</div><p class="cv-summary">${esc(x.summary||p.bio)}</p></section>`:''}
  ${cvList('Soft Skills',x.soft_skills)}${cvList('Hard Skills',x.hard_skills||p.skills)}${cvList('Education',x.education||p.qualifications)}${cvList('NYSC',x.nysc)}${cvList('Awards & Recognition',x.awards)}${cvList('Work Experience',x.work_experience)}${cvList('Professional Qualifications / Certifications',x.professional_certifications||p.certifications)}${credHtml}
  <section class="cv-section cv-meta"><div><span>Account</span><b>${esc(p.account_type||'individual')}</b></div><div><span>AVELYX Level</span><b>${esc(p.card_tier||'basic')}</b></div><div><span>Profile</span><b>Live & linked</b></div></section>
  ${publicMode?'<div class="cv-public-note">This Digital CV is linked to the member’s AVELYX identity. Contact details and protected information are not exposed here.</div>':'<div class="cv-actions"><a class="cv-btn" href="/profile.html">Edit Profile</a><a class="cv-btn ghost" href="/qr.html">Share Digital CV QR</a></div>'}</div>`;
}
function digitalCVStyles(){return `<style>.cv-wrap{max-width:900px;margin:0 auto;padding:22px 0 50px}.cv-top{display:flex;justify-content:space-between;align-items:center;padding:4px 2px 22px}.cv-brand{font-weight:950;letter-spacing:.24em;font-size:23px}.cv-emblem{width:52px;height:52px;border-radius:16px;border:1px solid #9b72ff;background:linear-gradient(145deg,#17102d,#080b18);display:grid;place-items:center;font-weight:950;font-size:23px;color:#fff;box-shadow:0 0 30px #8b4dff33}.cv-emblem span{font-size:9px;color:#8ee9bd;margin-left:-8px;margin-top:20px}.cv-hero{position:relative;display:flex;gap:24px;align-items:center;padding:30px;border:1px solid #2a3761;border-radius:30px;background:radial-gradient(circle at 90% 10%,#29115a,#0b1025 48%,#070b18);box-shadow:0 28px 80px #0009}.cv-avatar{width:132px;height:132px;object-fit:cover;border-radius:26px;border:1px solid #8b4dff;background:#10162e}.cv-kicker,.cv-section-title{font-size:10px;letter-spacing:.18em;color:#9c83e9;font-weight:900;text-transform:uppercase}.cv-identity h1{font-size:clamp(32px,5vw,54px);margin:7px 0 3px;letter-spacing:-1.5px}.cv-title{font-size:18px;color:#d3daf4;font-weight:700}.cv-id{font-size:11px;letter-spacing:.16em;color:#8290b7;margin-top:9px}.cv-motto{font-weight:900;color:#d8b85c;margin-top:10px}.cv-contact,.cv-location{display:flex;gap:14px;flex-wrap:wrap;color:#9ca9ca;font-size:12px;margin-top:10px}.cv-badge{display:inline-block;margin-top:13px;padding:7px 10px;border-radius:999px;border:1px solid #276247;color:#7ce2aa;font-size:10px;font-weight:900;letter-spacing:.08em}.cv-section{margin-top:17px;padding:23px;border:1px solid #202b50;border-radius:22px;background:linear-gradient(145deg,#0b1229,#080d1d)}.cv-section-title{margin-bottom:13px}.cv-summary{margin:0;color:#c3cbe4;line-height:1.75}.cv-list{display:grid;gap:9px}.cv-item{padding:13px 14px;border:1px solid #1b2748;border-radius:13px;background:#070c1b;color:#e8ecfa;line-height:1.5}.cv-item small{display:block;color:#8390b2;margin-top:4px}.cv-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.cv-meta div{padding:12px;border-radius:14px;background:#070c1b;border:1px solid #1b2748}.cv-meta span{display:block;font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:#7180a5}.cv-meta b{display:block;margin-top:5px;text-transform:capitalize}.cv-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.cv-btn{display:inline-block;text-decoration:none;padding:13px 17px;border-radius:13px;background:linear-gradient(135deg,#8b4dff,#5c39c9);color:#fff;font-weight:850}.cv-btn.ghost{background:#111a36;border:1px solid #273354}.cv-public-note{margin-top:18px;padding:14px;border-radius:14px;background:#0b1227;color:#8290b2;font-size:11px;line-height:1.6;text-align:center}@media(max-width:650px){.cv-hero{flex-direction:column;align-items:flex-start}.cv-avatar{width:100px;height:100px}.cv-meta{grid-template-columns:1fr}.cv-wrap{padding-left:2px;padding-right:2px}}</style>`}
async function digitalCVPage(request,env){
  const data=await getDigitalCV(request,env); if(!data) return Response.redirect(new URL('/login.html',request.url),302);
  return shell('Digital CV',digitalCVMarkup(data,false),digitalCVStyles()+memberGuardScript());
}
async function digitalCVApi(request,env){
  try{const data=await getDigitalCV(request,env); if(!data)return json({error:'Please log in.'},401); return json({ok:true,profile:data.profile,digital_cv:data.extra,credentials:data.credentials});}
  catch(e){return json({error:'Unable to load Digital CV.',detail:e?.message||String(e)},500)}
}
async function digitalCVSave(request,env){
  const user=await currentUser(request,env); if(!user)return json({error:'Please log in.'},401); await ensureDigitalCVTable(env);
  const b=await request.json().catch(()=>({}));
  const fields=['soft_skills','hard_skills','education','nysc','awards','work_experience','professional_certifications','summary'];
  const vals=fields.map(k=>String(b[k]||'').trim().slice(0,10000));
  await env.DB.prepare(`INSERT INTO digital_cv_data(profile_id,soft_skills,hard_skills,education,nysc,awards,work_experience,professional_certifications,summary,updated_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(profile_id) DO UPDATE SET soft_skills=excluded.soft_skills,hard_skills=excluded.hard_skills,education=excluded.education,nysc=excluded.nysc,awards=excluded.awards,work_experience=excluded.work_experience,professional_certifications=excluded.professional_certifications,summary=excluded.summary,updated_at=CURRENT_TIMESTAMP`).bind(user.id,...vals).run();
  return json({ok:true});
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
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(c.title)} • AVELYX</title>${styles()}</head><body><main class="public"><div class="brand">AVELYX<span>◆</span></div><section class="profile-card"><div class="eyebrow">AVELYX VERIFIED CREDENTIAL</div><h1>${esc(c.title)}</h1><p class="sub">${esc(c.full_name)}${c.organization?' · '+esc(c.organization):''}</p><div class="status ${c.status==='verified'?'':'bad'}">● ${esc(status)}</div><div class="fields"><div class="field"><span>Credential Type</span><strong>${esc(c.credential_type)}</strong></div><div class="field"><span>Issuer</span><strong>${esc(c.issuer||'Not provided')}</strong></div><div class="field"><span>Credential ID</span><strong>${esc(c.credential_id)}</strong></div><div class="field"><span>Verification Date</span><strong>${c.verified_at?new Date(c.verified_at*1000).toLocaleString():'Not yet verified'}</strong></div></div><div class="idbox"><small>AVELYX PROFILE</small><b>${esc(c.avx_id)}</b></div><p class="foot">Status reflects the current AVELYX verification record.</p></section></main></body></html>`,{headers:{'content-type':'text/html;charset=UTF-8'}});
}
function adminLoginPage(){return shell('Admin Access',`<section class="hero"><div class="eyebrow">AVELYX ADMIN</div><h1>Admin Control Center</h1><p class="muted">Sign in with the AVELYX account that is configured as the administrator. Your normal AVELYX login is used; admin access is an additional permission.</p></section><section class="panel admin-login-card"><label>Email</label><input id="adminEmail" type="email" autocomplete="username" placeholder="Admin email"><label>Password</label><input id="adminPassword" type="password" autocomplete="current-password" placeholder="Your AVELYX password"><div class="actions" style="margin-top:18px"><button class="btn" onclick="adminLogin()">Enter Admin</button><a class="btn ghost" href="/login.html">Member Login</a></div><div id="adminMsg"></div></section>`,`<script>async function adminLogin(){const email=document.getElementById('adminEmail').value.trim();const password=document.getElementById('adminPassword').value;const msg=document.getElementById('adminMsg');if(!email||!password){msg.className='error';msg.textContent='Enter your admin email and password.';return}const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email,password})});const d=await r.json().catch(()=>({}));if(!r.ok){msg.className='error';msg.textContent=d.error||'Login failed.';return}const c=await fetch('/api/admin/check',{credentials:'same-origin',cache:'no-store'});const cd=await c.json().catch(()=>({}));if(!c.ok){msg.className='error';msg.textContent=cd.error||'Admin access is not enabled for this account. Set ADMIN_EMAIL in Cloudflare Worker variables to this exact email.';return}location.href='/admin.html'}</script>`) }

function adminPage(){return shell('AVELYX Admin Control Center',`<section class="hero"><div class="eyebrow">AVELYX ADMIN</div><h1>Platform Control Center</h1><p class="muted">Manage AVX, credential pricing, verification payments, members, agents, jobs and future card approvals.</p><p class="muted"><b>Admin:</b> ${esc('Protected by ADMIN_EMAIL + AVELYX session')}</p></section>
<section class="panel"><div class="section-title-lite"><div><div class="eyebrow">CREDENTIAL PRICING</div><h2>Set verification price</h2></div><span class="status-chip good">1 AVX = ₦100</span></div><p class="muted">Prices are stored in the database. You can change them here later without rebuilding the website.</p><div id="priceList" class="admin-list">Loading pricing...</div></section>
<section class="panel" style="margin-top:16px"><div class="section-title-lite"><div><div class="eyebrow">PAYMENT APPROVALS</div><h2>Verification payments waiting for approval</h2></div></div><div id="paymentList">Loading...</div></section>
<section class="grid" style="margin-top:16px"><div class="panel"><div class="eyebrow">AVX WALLET CONTROL</div><h2>Adjust member AVX</h2><p class="muted">Positive amount adds AVX from the unlocked treasury. Negative amount removes AVX and returns it to the admin wallet.</p><label>Member AVELYX ID</label><input id="wavx" placeholder="AVX-..."><label>Adjustment (+/- AVX)</label><input id="wamount" type="number" placeholder="100 or -100"><label>Reference</label><input id="wref"><label>Note</label><input id="wnote"><button class="btn" style="margin-top:14px" onclick="adjustWallet()">Save Adjustment</button><div id="walletMsg"></div></div><div class="panel"><div class="eyebrow">ADMIN WALLET</div><h2 id="adminWalletBalance">0 AVX</h2><p class="muted">AVX collected from approved services and member adjustments.</p><div id="treasuryBox" class="field">Loading treasury...</div><label>Unlock AVX supply</label><input id="unlockAmount" type="number" placeholder="e.g. 1000000"><button class="btn ghost" style="margin-top:10px" onclick="unlockTreasury()">Unlock Supply</button><div id="treasuryMsg"></div></div></section>
<section class="panel" style="margin-top:16px"><div class="section-title-lite"><div><div class="eyebrow">AVX PACKAGES</div><h2>AVX purchase packages</h2></div><span class="status-chip good">₦100 / AVX</span></div><p class="muted">Package price must equal AVX amount × ₦100.</p><div class="grid"><div><label>Package name</label><input id="pname"></div><div><label>AVX amount</label><input id="pamount" type="number"></div><div><label>Price (NGN)</label><input id="pprice" type="number"></div><div><label>Sort order</label><input id="psort" type="number" value="0"></div><div class="wide"><label>Description</label><input id="pdesc"></div><div><label>Active</label><select id="pactive"><option value="1">Yes</option><option value="0">No</option></select></div></div><button class="btn" style="margin-top:14px" onclick="savePackage()">Save Package</button><div id="packages" style="margin-top:16px"></div></section>
<section class="panel" style="margin-top:16px"><div class="eyebrow">AGENTS</div><h2>Agent management</h2><p class="muted">Create, edit, activate or remove agents from the admin backend.</p><div class="grid"><input id="agentId" type="hidden"><div><label>Name</label><input id="agentName"></div><div><label>Email</label><input id="agentEmail"></div><div><label>Phone</label><input id="agentPhone"></div><div><label>State</label><input id="agentState"></div><div><label>Role</label><input id="agentRole" value="Agent"></div><div><label>Status</label><select id="agentStatus"><option value="active">Active</option><option value="inactive">Inactive</option></select></div><div class="wide"><label>Notes</label><textarea id="agentNotes"></textarea></div></div><button class="btn" style="margin-top:14px" onclick="saveAgent()">Save Agent</button><div id="agentMsg"></div><div id="agents" style="margin-top:16px"></div></section>
<section class="panel" style="margin-top:16px"><div class="eyebrow">CARD CONTROL</div><h2>Future card approvals</h2><p class="muted">Cards remain disabled for now. When cards are launched, eligible member orders can be approved here.</p><div id="cardOrders">Loading card orders...</div></section>
<section class="panel" style="margin-top:16px"><div class="eyebrow">PLATFORM CONTROLS</div><h2>Feature launches</h2><div id="settings" class="grid">Loading...</div></section>
<section class="panel" style="margin-top:16px"><div class="eyebrow">JOB LISTINGS</div><h2>Manage opportunities</h2><div class="grid"><div><label>Job title</label><input id="jtitle"></div><div><label>Employer</label><input id="jemployer"></div><div><label>Location</label><input id="jlocation"></div><div><label>Work mode</label><input id="jmode"></div><div><label>Employment type</label><input id="jtype"></div><div><label>Minimum experience</label><input id="jexp" type="number" value="0"></div><div class="wide"><label>Required skills</label><input id="jskills"></div><div class="wide"><label>Required qualifications</label><input id="jquals"></div><div class="wide"><label>Required certificates</label><input id="jcerts"></div><div class="wide"><label>Application URL</label><input id="jurl"></div></div><button class="btn" style="margin-top:14px" onclick="saveJob()">Add Job</button><div id="jobs" style="margin-top:16px"></div></section>
<section class="panel" style="margin-top:16px"><div class="eyebrow">CREDENTIAL RECORDS</div><h2>Admin-issued credentials</h2><div class="grid"><div><label>Member AVELYX ID</label><input id="cavx"></div><div><label>Credential title</label><input id="ctitle"></div><div><label>Credential type</label><input id="ctype"></div><div><label>Issuer</label><input id="cissuer"></div><div><label>Reference</label><input id="cref"></div><div><label>Status</label><select id="cstatus"><option value="pending">Pending</option><option value="verified">Verified</option><option value="unverified">Unverified</option></select></div></div><button class="btn" style="margin-top:14px" onclick="createCredential()">Issue Credential</button><div id="credentialMsg"></div><div id="credentialsAdmin" style="margin-top:16px">Loading...</div></section>`,`<script>
let data;const esc=(s)=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load(){const r=await fetch('/api/admin/platform',{credentials:'same-origin',cache:'no-store'});const d=await r.json().catch(()=>({}));if(!r.ok){document.body.innerHTML='<main class="public"><section class="profile-card"><h1>Admin access required</h1><p class="sub">Check ADMIN_EMAIL and sign in again through Admin Access.</p><a class="btn" href="/admin-login.html">Admin Access</a></section></main>';return}data=d;document.getElementById('adminWalletBalance').textContent=Number(d.admin_wallet?.balance||0).toLocaleString()+' AVX';const prices=d.credential_prices||[];priceList.innerHTML=prices.map(x=>'<div class="field"><b>'+esc(x.credential_type.replace(/\b\w/g,m=>m.toUpperCase()))+'</b><br><input id="price_'+x.credential_type.replace(/[^a-z0-9]/g,'_')+'" type="number" min="0" value="'+Number(x.avx_cost||0)+'" placeholder="AVX price"><select id="active_'+x.credential_type.replace(/[^a-z0-9]/g,'_')+'"><option value="1" '+(Number(x.active)===1?'selected':'')+'>Active</option><option value="0" '+(Number(x.active)!==1?'selected':'')+'>Not set</option></select> <button class="btn ghost" onclick="savePrice(\''+x.credential_type+'\')">Save</button></div>').join('');paymentList.innerHTML=(d.verification_payments||[]).map(x=>'<div class="field"><b>'+esc(x.full_name)+' · '+esc(x.credential_type)+'</b><br><small>'+esc(x.avx_id)+' · '+esc(x.institution_name)+' · '+Number(x.avx_cost||0)+' AVX · balance '+Number(x.avx_balance||0)+' AVX</small><br><span class="pill">PENDING PAYMENT</span> · '+esc(x.reference||'')+'<div class="actions" style="margin-top:10px"><button class="btn" onclick="payment('+x.id+',\'approve\')">Approve & Collect AVX</button><button class="btn ghost" onclick="payment('+x.id+',\'reject\')">Reject</button></div></div>').join('')||'<p class="muted">No verification payments waiting.</p>';const t=d.treasury;if(t)treasuryBox.innerHTML='<b>Maximum:</b> '+Number(t.max_supply||0).toLocaleString()+' AVX<br><b>Unlocked:</b> '+Number(t.unlocked_amount||0).toLocaleString()+' AVX<br><b>Issued:</b> '+Number(t.issued_amount||0).toLocaleString()+' AVX';packages.innerHTML=(d.packages||[]).map(p=>'<div class="field"><b>'+esc(p.name)+'</b> · '+Number(p.avx_amount).toLocaleString()+' AVX · ₦'+Number(p.price_ngn).toLocaleString()+'<br><small>'+esc(p.description||'')+' · '+(p.active?'ACTIVE':'DRAFT')+'</small><br><button class="btn ghost" onclick="editPackage('+p.id+')">Edit</button> <button class="btn ghost" onclick="deletePackage('+p.id+')">Delete</button></div>').join('')||'<p class="muted">No packages.</p>';agents.innerHTML=(d.agents||[]).map(a=>'<div class="field"><b>'+esc(a.name)+'</b> · '+esc(a.role)+' · <span class="pill">'+esc(a.status.toUpperCase())+'</span><br><small>'+esc(a.email||'')+' · '+esc(a.phone||'')+' · '+esc(a.state||'')+'</small><br><button class="btn ghost" onclick="editAgent('+a.id+')">Edit</button> <button class="btn ghost" onclick="deleteAgent('+a.id+')">Delete</button></div>').join('')||'<p class="muted">No agents.</p>';cardOrders.innerHTML=(d.card_orders||[]).map(c=>'<div class="field"><b>'+esc(c.full_name)+' · '+esc(c.card_tier)+'</b><br><small>'+esc(c.avx_id)+' · '+esc(c.status)+' · '+esc(c.reference)+'</small>'+(c.status==='pending_payment'?'<br><button class="btn ghost" onclick="cardStatus('+c.id+',\'approved\')">Approve Card</button> <button class="btn ghost" onclick="cardStatus('+c.id+',\'rejected\')">Reject</button>':'')+'</div>').join('')||'<p class="muted">No card orders. Cards are currently disabled.</p>';const labels={avx_enabled:'AVX Credits',global_search_enabled:'Global Search',verified_credentials_enabled:'Verified Credentials',verify_mark_enabled:'Verify Credential Mark',cards_enabled:'AVELYX Cards',job_search_enabled:'Job Search'};settings.innerHTML=Object.entries(labels).map(([k,v])=>'<div class="field"><b>'+v+'</b><br><span class="pill">'+(d.settings[k]==='1'?'LIVE':'OFF')+'</span><br><button class="btn ghost" onclick="toggleSetting(\''+k+'\','+(d.settings[k]==='1'?'false':'true')+')">'+(d.settings[k]==='1'?'Turn Off':'Launch')+'</button></div>').join('');jobs.innerHTML=(d.jobs||[]).map(j=>'<div class="field"><b>'+esc(j.title)+'</b> · '+esc(j.employer)+'<br><small>'+esc(j.location||'')+' · '+(j.active?'ACTIVE':'OFF')+'</small><br><button class="btn ghost" onclick="toggleJob('+j.id+','+(!j.active)+')">'+(j.active?'Deactivate':'Activate')+'</button> <button class="btn ghost" onclick="deleteJob('+j.id+')">Delete</button></div>').join('')||'<p class="muted">No jobs.</p>';const cr=await fetch('/api/admin/credentials',{credentials:'same-origin'});const cd=await cr.json().catch(()=>({}));credentialsAdmin.innerHTML=(cd.credentials||[]).map(c=>'<div class="field"><b>'+esc(c.full_name)+' · '+esc(c.title)+'</b><br><span class="pill">'+esc(String(c.status).toUpperCase())+'</span> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'verified\')">Verify</button> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'revoked\')">Revoke</button></div>').join('')||'<p class="muted">No credentials.</p>'}
async function savePrice(type){const k=type.replace(/[^a-z0-9]/g,'_');const r=await fetch('/api/admin/credential-prices',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_type:type,avx_cost:Number(document.getElementById('price_'+k).value||0),active:document.getElementById('active_'+k).value==='1'})});const d=await r.json();if(!r.ok)return alert(d.error||'Unable to save price');load()}
async function payment(id,decision){if(decision==='approve'&&!confirm('Approve this payment and collect the AVX from the member wallet?'))return;const r=await fetch('/api/admin/verification/payment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,decision})});const d=await r.json();if(!r.ok)return alert(d.error||'Unable to process payment');load()}
async function adjustWallet(){const r=await fetch('/api/admin/wallet/adjust',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({avx_id:wavx.value,amount:wamount.value,reference:wref.value,note:wnote.value})});const d=await r.json();walletMsg.className=r.ok?'toast':'error';walletMsg.textContent=r.ok?'Wallet updated. New balance: '+d.new_balance+' AVX. Admin wallet: '+d.admin_wallet_balance+' AVX':d.error;load()}
async function unlockTreasury(){const r=await fetch('/api/admin/treasury/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({amount:unlockAmount.value})});const d=await r.json();treasuryMsg.className=r.ok?'toast':'error';treasuryMsg.textContent=r.ok?'Unlocked successfully.':d.error;load()}
async function savePackage(){const b={id:window.editingPackage||null,name:pname.value,price_ngn:pprice.value,avx_amount:pamount.value,description:pdesc.value,active:pactive.value==='1',sort_order:psort.value};const r=await fetch('/api/admin/packages',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok)return alert(d.error);window.editingPackage=null;load()}
function editPackage(id){const p=data.packages.find(x=>x.id===id);if(!p)return;window.editingPackage=id;pname.value=p.name;pprice.value=p.price_ngn;pamount.value=p.avx_amount;pdesc.value=p.description||'';psort.value=p.sort_order||0;pactive.value=p.active?'1':'0';pname.scrollIntoView({behavior:'smooth'})}async function deletePackage(id){if(!confirm('Delete package?'))return;await fetch('/api/admin/packages/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}
async function saveAgent(){const b={id:agentId.value||null,name:agentName.value,email:agentEmail.value,phone:agentPhone.value,state:agentState.value,role:agentRole.value,status:agentStatus.value,notes:agentNotes.value};const r=await fetch('/api/admin/agents',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();agentMsg.className=r.ok?'toast':'error';agentMsg.textContent=r.ok?'Agent saved.':d.error;load()}
function editAgent(id){const a=data.agents.find(x=>x.id===id);if(!a)return;agentId.value=a.id;agentName.value=a.name;agentEmail.value=a.email||'';agentPhone.value=a.phone||'';agentState.value=a.state||'';agentRole.value=a.role||'Agent';agentStatus.value=a.status||'active';agentNotes.value=a.notes||'';agentName.scrollIntoView({behavior:'smooth'})}async function deleteAgent(id){if(!confirm('Delete this agent?'))return;await fetch('/api/admin/agents/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}
async function cardStatus(id,status){const r=await fetch('/api/admin/cards/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,status})});const d=await r.json();if(!r.ok)return alert(d.error);load()}
async function toggleSetting(key,value){const r=await fetch('/api/admin/platform/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key,value})});if(!r.ok)return alert((await r.json()).error);load()}
async function saveJob(){const b={title:jtitle.value,employer:jemployer.value,location:jlocation.value,work_mode:jmode.value,employment_type:jtype.value,min_experience:jexp.value,required_skills:jskills.value,required_qualifications:jquals.value,required_certificates:jcerts.value,apply_url:jurl.value,active:true};const r=await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok)return alert(d.error);load()}
async function toggleJob(id,on){const j=data.jobs.find(x=>x.id===id);const b={...j,active:on};await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});load()}async function deleteJob(id){if(!confirm('Delete job?'))return;await fetch('/api/admin/jobs/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}
async function createCredential(){const b={avx_id:cavx.value,title:ctitle.value,credential_type:ctype.value,issuer:cissuer.value,reference:cref.value,status:cstatus.value};const r=await fetch('/api/admin/credentials',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();credentialMsg.className=r.ok?'toast':'error';credentialMsg.textContent=r.ok?'Created '+d.credential_id:d.error;load()}async function setCredential(id,status){const r=await fetch('/api/admin/credentials/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_id:id,status})});if(!r.ok)alert((await r.json()).error);load()}load()</script>`) }


export default { async fetch(request, env) {
  const url = new URL(request.url);
  try {
    if (url.pathname === '/api/register' && request.method === 'POST') return await register(request, env);
    if (url.pathname === '/api/login' && request.method === 'POST') return await login(request, env);
    if (url.pathname === '/api/platform' && request.method === 'GET') return await platformConfig(request, env);
    if (url.pathname === '/api/jobs/recommendations' && request.method === 'GET') return await jobRecommendations(request, env);
    if (url.pathname === '/api/admin/check' && request.method === 'GET') { const a=await requireAdmin(request,env); return a ? json({ok:true,email:a.login_email}) : adminDenied(); }
    if (url.pathname === '/api/admin/platform' && request.method === 'GET') return await adminPlatform(request, env);
    if (url.pathname === '/api/admin/platform/settings' && request.method === 'POST') return await adminSetSetting(request, env);
    if (url.pathname === '/api/verification/prices' && request.method === 'GET') return await verificationPrices(request, env);
    if (url.pathname === '/api/admin/credential-prices' && request.method === 'GET') return await adminCredentialPrices(request, env);
    if (url.pathname === '/api/admin/credential-prices' && request.method === 'POST') return await adminSaveCredentialPrice(request, env);
    if (url.pathname === '/api/admin/wallet/adjust' && request.method === 'POST') return await adminAdjustWallet(request, env);
    if (url.pathname === '/api/admin/agents' && request.method === 'GET') return await adminAgents(request, env);
    if (url.pathname === '/api/admin/agents' && request.method === 'POST') return await adminSaveAgent(request, env);
    if (url.pathname === '/api/admin/agents/delete' && request.method === 'POST') return await adminDeleteAgent(request, env);
    if (url.pathname === '/api/admin/cards' && request.method === 'GET') return await adminCardOrders(request, env);
    if (url.pathname === '/api/admin/cards/status' && request.method === 'POST') return await adminCardStatus(request, env);
    if (url.pathname === '/api/admin/verification/payment' && request.method === 'POST') return await adminApproveVerificationPayment(request, env);
    if (url.pathname === '/api/admin/packages' && request.method === 'POST') return await adminSavePackage(request, env);
    if (url.pathname === '/api/admin/packages/delete' && request.method === 'POST') return await adminDeletePackage(request, env);
    if (url.pathname === '/api/admin/wallet/credit' && request.method === 'POST') return await adminCreditWallet(request, env);
    if (url.pathname === '/api/admin/treasury/unlock' && request.method === 'POST') return await adminUnlockTreasury(request, env);
    if (url.pathname === '/api/admin/jobs' && request.method === 'GET') return await adminJobs(request, env);
    if (url.pathname === '/api/admin/jobs' && request.method === 'POST') return await adminSaveJob(request, env);
    if (url.pathname === '/api/admin/jobs/delete' && request.method === 'POST') return await adminDeleteJob(request, env);
    if (url.pathname === '/api/institutions' && request.method === 'GET') return await institutionsList(request, env);
    if (url.pathname === '/api/institution-requests' && request.method === 'POST') return await requestInstitution(request, env);
    if (url.pathname === '/api/verification/requests' && request.method === 'GET') return await verificationRequestsV2(request, env);
    if (url.pathname === '/api/verification/submit' && request.method === 'POST') return await submitCredentialVerification(request, env);
    if (url.pathname === '/api/admin/institutions' && request.method === 'GET') return await adminInstitutions(request, env);
    if (url.pathname === '/api/admin/institutions' && request.method === 'POST') return await adminSaveInstitution(request, env);
    if (url.pathname === '/api/admin/verification' && request.method === 'GET') return await adminVerificationCenter(request, env);
    if (url.pathname === '/api/admin/verification' && request.method === 'POST') return await adminUpdateVerification(request, env);
    if (url.pathname === '/api/admin/verification-cost' && request.method === 'POST') return await adminVerificationCost(request, env);
    if (url.pathname === '/admin-verification-document.html' && request.method === 'GET') return await adminVerificationDocument(request, env);
    if (url.pathname === '/api/digital-cv' && request.method === 'GET') return await digitalCVApi(request, env);
    if (url.pathname === '/api/digital-cv' && request.method === 'PUT') return await digitalCVSave(request, env);
    if (url.pathname === '/api/credentials' && request.method === 'GET') return await myCredentials(request, env);
    if (url.pathname === '/api/information-requests/sent' && request.method === 'GET') return await sentInformationRequests(request, env);
    if (url.pathname === '/api/information-requests' && request.method === 'GET') return await informationRequests(request, env);
    if (url.pathname === '/api/information-requests' && request.method === 'POST') return await createInformationRequest(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'GET') return await adminCredentials(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'POST') return await adminCreateCredential(request, env);
    if (url.pathname === '/api/admin/credentials/status' && request.method === 'POST') return await adminUpdateCredential(request, env);
    if (url.pathname === '/api/logout' && request.method === 'POST') return await logout(request, env);
    if (url.pathname === '/api/me') return await me(request, env);
    if (url.pathname === '/api/profile/photo' && request.method === 'GET') return await profilePhoto(request, env);
    if (url.pathname === '/api/profile/photo' && request.method === 'POST') return await uploadProfilePhoto(request, env);
    if (url.pathname === '/api/profile/lock' && request.method === 'POST') return await lockProfile(request, env, false);
    if (url.pathname === '/api/profile/unlock' && request.method === 'POST') return await lockProfile(request, env, true);
    if (url.pathname === '/api/avx/history' && request.method === 'GET') return await avxHistory(request, env);
    if (url.pathname === '/api/profile' && request.method === 'PUT') return await updateProfile(request, env);
    if (url.pathname === '/api/profile/upgrade' && request.method === 'POST') return await upgradeProfile(request, env);
    if (url.pathname === '/api/card/status' && request.method === 'GET') return await cardStatus(request, env);
    if (url.pathname === '/api/card/purchase' && request.method === 'POST') return await cardPurchase(request, env);
    if (url.pathname.startsWith('/api/information-requests/') && url.pathname.endsWith('/respond') && request.method === 'POST') return await respondInformationRequest(request, env, url.pathname.split('/')[3]);
    if (url.pathname.startsWith('/api/information-requests/') && url.pathname.endsWith('/data') && request.method === 'GET') return await permittedInformation(request, env, url.pathname.split('/')[3]);
    if (url.pathname === '/api/share' && request.method === 'POST') return await generateShare(request, env);
    if (url.pathname.startsWith('/s/')) return await scanShare(url.pathname.slice(3), env);
    if (url.pathname.startsWith('/c/')) return await publicCredential(request, env, url.pathname.slice(3));
    if (url.pathname === '/admin.html') { const a=await requireAdmin(request,env); return a ? adminPage() : new Response('Admin access required',{status:403}); }
    if (url.pathname.startsWith('/v/')) { const data=await getDigitalCV({headers:new Headers()},env,url.pathname.slice(3)); return data ? new Response(`<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>AVELYX Digital CV • ${esc(data.profile.avx_id)}</title>${styles()}${digitalCVStyles()}</head><body><div class=\"app\"><main class=\"app-content\">${digitalCVMarkup(data,true)}</main></div></body></html>`,{headers:{'content-type':'text/html;charset=UTF-8'}}) : new Response('Profile not found',{status:404}); }
    if (appPages[url.pathname] === 'register') return registerPage();
    if (appPages[url.pathname] === 'login') return loginPage();
    if (appPages[url.pathname] === 'verify') return verifyPage();
    if (appPages[url.pathname] === 'admin-login') return adminLoginPage();
    if (appPages[url.pathname] === 'dashboard') return await dashboardPage(request, env);
    if (appPages[url.pathname] === 'profile') return await profilePage(request, env);
    if (appPages[url.pathname] === 'verification') return verificationPage();
    if (url.pathname === '/admin-institutions.html') { const a=await requireAdmin(request,env); return a ? adminInstitutionsPage() : new Response('Admin access required',{status:403}); }
    if (appPages[url.pathname] === 'qr') return qrPage();
    if (appPages[url.pathname] === 'permissions') return permissionsPage();
    if (appPages[url.pathname] === 'notifications') return notificationsPage();
    if (appPages[url.pathname] === 'wallet') return walletPage();
    if (appPages[url.pathname] === 'opportunities') return opportunitiesPage();
    if (appPages[url.pathname] === 'digital-cv') return await digitalCVPage(request,env);
    return env.ASSETS.fetch(request);
  } catch (e) { return json({ error: 'Server error. Please try again.', detail: e?.message || String(e) }, 500); }
}};
