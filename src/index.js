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
  return env.DB.prepare(`SELECT u.id AS user_id, u.email AS login_email, p.*, COALESCE(w.balance, 0) AS avx_balance FROM sessions s JOIN users u ON u.id=s.user_id JOIN profiles p ON p.id=u.profile_id LEFT JOIN wallets w ON w.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash, now()).first();
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
    await env.DB.prepare('INSERT OR IGNORE INTO wallets (user_id, balance) VALUES (?, 0)').bind(userId).run();
  } catch (e) {
    await env.DB.prepare('DELETE FROM profiles WHERE id=?').bind(profileId).run();
    throw e;
  }

  const token = await createSession(userId, env);
  return withSession(json({ ok: true, avx_id: avxId, message: 'Account created successfully.' }, 201), token);
}
async function ensureCredentialsTable(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY AUTOINCREMENT,credential_id TEXT NOT NULL UNIQUE,profile_id INTEGER NOT NULL,credential_type TEXT NOT NULL,title TEXT NOT NULL,issuer TEXT,reference TEXT,status TEXT NOT NULL DEFAULT 'pending',verified_at INTEGER,expires_at INTEGER,notes TEXT,created_by_admin_email TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_credentials_profile_id ON credentials(profile_id)').run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status)').run();
}
async function ensureVerificationRequestsTable(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS verification_requests (id INTEGER PRIMARY KEY AUTOINCREMENT,profile_id INTEGER NOT NULL,verification_type TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',evidence TEXT,notes TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE)`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_verification_requests_profile ON verification_requests(profile_id,status,created_at)').run();
}
async function verificationRequests(request, env) {
  await ensureVerificationRequestsTable(env);
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const rows=await env.DB.prepare('SELECT id,verification_type,status,evidence,notes,created_at,updated_at FROM verification_requests WHERE profile_id=? ORDER BY id DESC').bind(user.id).all();
  return json({requests:rows.results||[]});
}
async function createVerificationRequest(request, env) {
  await ensureVerificationRequestsTable(env);
  const user=await currentUser(request,env); if(!user) return json({error:'Please log in.'},401);
  const b=await request.json().catch(()=>({})); const type=String(b.verification_type||'').trim().toLowerCase();
  const allowed=['identity','education','employment','certification','business']; if(!allowed.includes(type)) return json({error:'Invalid verification type.'},400);
  const existing=await env.DB.prepare("SELECT id FROM verification_requests WHERE profile_id=? AND verification_type=? AND status IN ('pending','accepted') ORDER BY id DESC LIMIT 1").bind(user.id,type).first();
  if(existing) return json({error:'A verification request is already pending for this category.'},409);
  const evidence=String(b.evidence||'').trim().slice(0,1000);
  await env.DB.prepare('INSERT INTO verification_requests (profile_id,verification_type,status,evidence,notes) VALUES (?,?,?,?,?)').bind(user.id,type,'pending',evidence,'Member verification request').run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(user.user_id,'verification.request','profile',user.avx_id,JSON.stringify({verification_type:type})).run();
  return json({ok:true,message:'Verification request submitted. AVELYX will review it and update the status.'},201);
}
async function cardEligibility(user, env) {
  await ensureCredentialsTable(env);
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
    env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(user.user_id,'profile.upgrade','profile',user.avx_id,JSON.stringify({from:current,to:target,card_tier:card}))
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
  return renderPublic(profile, fields, `Secure AVELYX Share • ${profile.avx_id}`, true);
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
function styles() { return `<style>:root{--bg:#050817;--panel:#0c1430;--line:#202b50;--text:#f7f8ff;--muted:#9ca9ca;--purple:#8b4dff;--blue:#159cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#17153c 0,#050817 42%);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}.public{max-width:760px;margin:auto;padding:48px 20px}.brand{font-weight:900;font-size:26px;letter-spacing:.18em;margin-bottom:34px}.brand span{color:var(--blue);font-size:12px;margin-left:8px}.profile-card{background:linear-gradient(145deg,#111a3a,#080d21);border:1px solid var(--line);border-radius:28px;padding:34px;box-shadow:0 24px 70px #0008}.center{text-align:center}.eyebrow{font-size:11px;letter-spacing:.18em;color:#8ea3d8;font-weight:800}h1{font-size:42px;line-height:1.05;margin:14px 0 8px}.sub{color:var(--muted);font-size:17px}.status{display:inline-block;margin:18px 0;padding:8px 12px;border:1px solid #275f49;border-radius:999px;color:#67e0a1;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.status.bad{border-color:#693345;color:#ff879e}.fields{display:grid;gap:10px;margin-top:12px}.field{padding:15px;border:1px solid #1d2748;border-radius:14px;background:#070c1d}.field span{display:block;color:#7785aa;font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:5px}.field strong{font-size:15px;word-break:break-word}.field a{color:#65baff}.idbox{margin-top:18px;padding:18px;border-radius:16px;background:#0a1229;border:1px solid #27365e}.idbox small{display:block;color:#7484a8;font-size:10px;letter-spacing:.14em}.idbox b{display:block;margin-top:5px;letter-spacing:.1em}.notice{color:#ffbd68;font-size:13px}.foot{text-align:center;color:#657294;margin-top:24px;font-size:12px}</style>`; }

const appPages = {
  '/register.html': 'register', '/login.html':'login', '/verify-email.html':'verify', '/dashboard.html':'dashboard',
  '/profile.html':'profile', '/qr.html':'qr', '/permissions.html':'permissions', '/notifications.html':'notifications', '/wallet.html':'wallet', '/opportunities.html':'opportunities'
};
function shell(title, content, script='') { return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} • AVELYX</title>${styles()}<style>.app{max-width:1050px;margin:auto;padding:24px 18px 60px}.nav{display:flex;justify-content:space-between;align-items:center;padding:10px 0 34px}.nav a{color:#b8c3e1;text-decoration:none;margin-left:18px}.btn{border:0;border-radius:12px;padding:13px 18px;font-weight:800;cursor:pointer;color:white;background:linear-gradient(135deg,var(--purple),var(--blue));box-shadow:0 10px 30px #315bff22}.btn.ghost{background:#111a36;border:1px solid var(--line);box-shadow:none}.notify-btn{position:absolute;right:4px;top:4px;width:48px;height:48px;border-radius:16px;border:1px solid var(--line);background:#111a36;color:#fff;font-size:21px;cursor:pointer}.notify-badge{position:absolute;right:-4px;top:-5px;min-width:20px;height:20px;padding:0 5px;border-radius:999px;background:#ff477e;color:#fff;font:800 11px/20px system-ui;justify-content:center;align-items:center}.permission-checks{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}.check{margin:0;padding:10px;border:1px solid var(--line);border-radius:10px;background:#070c1d}.check input{width:auto;margin-right:8px}.permission-card{margin-bottom:10px}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.panel{background:#0b122a;border:1px solid var(--line);border-radius:22px;padding:24px}.panel h2{margin-top:0}.muted{color:var(--muted)}label{display:block;font-size:12px;color:#9aa8c9;margin:13px 0 7px}input,textarea,select{width:100%;padding:13px 14px;border-radius:12px;border:1px solid #263354;background:#070d20;color:white;outline:none}textarea{min-height:100px;resize:vertical}.wide{grid-column:1/-1}.toast{margin-top:12px;color:#7ee8b1}.error{color:#ff91a5;margin-top:12px}.hero{padding:34px 0 22px}.hero h1{font-size:46px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.soon{opacity:.62;position:relative;overflow:hidden}.soon:after{content:'COMING SOON';position:absolute;top:15px;right:-31px;transform:rotate(35deg);background:#1d2850;padding:6px 38px;font-size:9px;letter-spacing:.12em}.card-showcase{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.card-image{width:100%;display:block;border-radius:18px;border:1px solid #29365c;box-shadow:0 20px 50px #0008}.soon-label{display:inline-block;margin:0 0 10px;padding:5px 9px;border-radius:999px;background:#101b3b;color:#a9b9df;font-size:9px;letter-spacing:.14em;font-weight:900}@media(max-width:760px){.card-showcase{grid-template-columns:1fr}}.qrbox{text-align:center}.qrbox canvas,.qrbox img{max-width:260px;margin:16px auto;display:block;background:white;padding:10px;border-radius:14px}.pill{display:inline-block;padding:7px 10px;border-radius:999px;background:#101b3b;color:#9eb1de;font-size:11px}.share-url{word-break:break-all;color:#73bdff;font-size:12px}.actions{display:flex;gap:10px;flex-wrap:wrap}.avx-actions{display:flex;gap:14px;margin-top:18px}.avx-icon{width:52px;height:52px;border-radius:16px;border:1px solid #202a49;background:#070b16;color:#46506d;font-size:24px;font-weight:900;cursor:not-allowed;box-shadow:none}.avx-icon.locked{opacity:.45;filter:grayscale(1)}.avx-icon svg{width:24px;height:24px;display:block;margin:auto}@media(max-width:760px){.grid,.cards{grid-template-columns:1fr}.hero h1{font-size:35px}h1{font-size:34px}}</style></head><body><div class="app"><nav class="nav"><a href="/" style="font-weight:900;font-size:22px;letter-spacing:.15em;color:white">AVELYX</a><div><a href="/dashboard.html">Dashboard</a><a href="/login.html">Login</a></div></nav>${content}</div>${script}</body></html>`, {headers:{'content-type':'text/html; charset=UTF-8'}}); }
function registerPage(){return shell('Create AVELYX Account',`<section class="hero"><div class="eyebrow">JOIN AVELYX</div><h1>Create your AVELYX Account.</h1><p class="muted">Choose the identity that best describes you. You can grow from Individual to Entrepreneur and later to Business without losing your AVELYX identity.</p></section><section class="panel"><div class="grid"><div class="wide"><label>Profile type *</label><select id="account_type" onchange="toggleAccountType()"><option value="individual">Basic — Individual</option><option value="entrepreneur">Platinum — Entrepreneur / Professional</option><option value="business">Gold — Business / Organization</option></select></div><div class="wide"><label id="nameLabel">Full name *</label><input id="full_name" placeholder="Your full name"></div><div id="businessFields" class="wide" style="display:none"><div class="grid"><div><label>Business / organization name *</label><input id="organization" placeholder="Registered business or organization"></div><div><label>CAC registration number <span class="muted">(optional at registration)</span></label><input id="cac_number" placeholder="CAC / RC number"></div></div></div><div><label>Email *</label><input id="email" type="email" placeholder="you@example.com"></div><div><label>Password *</label><input id="password" type="password" minlength="8" required placeholder="8+ chars, A-Z, a-z, 0-9"><small class="muted">Use at least 8 characters with uppercase, lowercase and a number.</small></div><div><label>Professional title</label><input id="title" placeholder="e.g. Software Developer / Founder"></div><div id="orgIndividual"><label>Organization / Business</label><input id="organization_individual" placeholder="Company, school or business"></div><div><label>Industry</label><input id="industry" placeholder="e.g. Technology"></div><div><label>Location</label><input id="location" placeholder="City, Country"></div><div><label>Phone</label><input id="phone" placeholder="Optional"></div><div><label>Website</label><input id="website" placeholder="https://..."></div><div class="wide"><label>Short bio</label><textarea id="bio" placeholder="Tell people what you do..."></textarea></div><div class="wide actions"><button class="btn" onclick="registerAccount()">Create AVELYX Account</button><span id="msg"></span></div></div></section>`,`<script>function toggleAccountType(){const type=account_type.value;const business=type==='business';businessFields.style.display=business?'block':'none';orgIndividual.style.display=business?'none':'block';nameLabel.textContent=business?'Authorized representative full name *':'Full name *'}async function registerAccount(){const type=account_type.value;const business=type==='business';const body={account_type:type,full_name:full_name.value,email:email.value,password:password.value,title:title.value,organization:business?document.getElementById('organization').value:document.getElementById('organization_individual').value,industry:industry.value,location:location.value,phone:phone.value,website:website.value,bio:bio.value,cac_number:business?cac_number.value:''};const r=await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}msg.className='toast';msg.innerHTML='Account created: <b>'+d.avx_id+'</b>';setTimeout(()=>location.href='/dashboard.html',500)}toggleAccountType()</script>`);}

function verifyPage(){return shell('Verify Email',`<section class="hero"><div class="eyebrow">SECURE YOUR AVELYX ACCOUNT</div><h1>Verify your email.</h1><p class="muted">Enter the 6-digit code we sent to your email address.</p></section><section class="panel" style="max-width:560px"><label>Email</label><input id="email" type="email" placeholder="you@example.com"><label>Verification code</label><input id="code" inputmode="numeric" maxlength="6" placeholder="000000"><div class="actions" style="margin-top:18px"><button class="btn" onclick="verify()">Verify Email</button><button class="btn ghost" onclick="resend()">Resend Code</button><a class="btn ghost" href="/login.html">Login</a></div><div id="msg"></div></section>`,`<script>email.value=new URLSearchParams(location.search).get('email')||'';async function verify(){const r=await fetch('/api/verify-email',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,code:code.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}msg.className='toast';msg.textContent='Email verified. Redirecting...';setTimeout(()=>location.href='/dashboard.html',500)}async function resend(){const r=await fetch('/api/resend-verification',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value})});const d=await r.json();const msg=document.getElementById('msg');msg.className=r.ok?'toast':'error';msg.textContent=d.message||d.error}</script>`);}
function loginPage(){return shell('Login',`<section class="hero"><div class="eyebrow">AVELYX MEMBER ACCESS</div><h1>Welcome back.</h1><p class="muted">Access your profile, secure QR tools and member features.</p></section><section class="panel" style="max-width:560px"><label>Email</label><input id="email" type="email"><label>Password</label><input id="password" type="password"><div class="actions" style="margin-top:18px"><button class="btn" onclick="login()">Log In</button><a class="btn ghost" href="/register.html">Create Account</a></div><div id="msg"></div></section>`,`<script>async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;if(d.needs_verification)msg.innerHTML=d.error+' <a href="/verify-email.html?email='+encodeURIComponent(email.value)+'" style="color:#73bdff">Verify email</a>';return}if(d.requires_2fa){document.querySelector('.panel').innerHTML='<label>Authenticator code</label><input id="code" inputmode="numeric" maxlength="6" placeholder="000000"><div class="actions" style="margin-top:18px"><button class="btn" onclick="finish2fa()">Continue</button></div><div id="msg"></div>';return}location.href='/dashboard.html'}async function finish2fa(){const r=await fetch('/api/login/2fa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:code.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}location.href='/dashboard.html'}</script>`);}
function memberGuardScript(){return `<script>async function me(){const r=await fetch('/api/me',{credentials:'same-origin'});if(!r.ok){location.href='/login.html';return null}const d=await r.json();return d.profile}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/'}function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}function attr(s){return String(s??'').replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</script>`}
function dashboardPage(){return shell('Dashboard',`<section class="dash-hero"><div class="dash-copy"><div class="eyebrow">AVELYX • PROFESSIONAL IDENTITY</div><h1 id="welcome">Build a profile people can trust.</h1><p>Prove your potential with one professional identity, verified credentials and opportunities built around what you can actually show.</p><div class="dash-actions"><a class="btn" href="/profile.html">Open My Profile</a><a class="btn ghost" href="/qr.html">Share My QR</a></div></div><div class="dash-mark" aria-label="AVELYX Verification Logo"><div class="mark-orbit"></div><div class="mark-core"><span class="verify-crown">♛</span><span class="verify-letter">A</span><span class="verify-badge">✓</span></div><small>AVELYX VERIFIED</small></div></section><section class="dash-grid"><a class="dash-tile featured" href="/profile.html"><span>01</span><b>My Professional Identity</b><small>Keep your AVELYX profile complete and ready to share.</small></a><a class="dash-tile" href="/qr.html"><span>02</span><b>Secure QR</b><small>Share your professional profile in one scan.</small></a><a class="dash-tile" href="/permissions.html"><span>03</span><b>Information Permissions</b><small>Control what verified information you share.</small></a><a class="dash-tile" href="/notifications.html"><span>04</span><b>Notifications</b><small>Stay informed about requests and account activity.</small><span id="notificationBadge" class="badge" style="display:none">0</span></a><a class="dash-tile" href="/wallet.html"><span>05</span><b>AVX Wallet</b><small>View your AVX balance and account activity.</small></a><a class="dash-tile" href="/opportunities.html"><span>06</span><b>Opportunities</b><small>Discover professional opportunities through AVELYX.</small></a></section><section class="grid dash-bottom"><div class="panel"><div class="eyebrow">YOUR AVELYX LEVEL</div><h2 id="levelTitle">Profile Level</h2><div id="identityBox" class="identity-card">Loading...</div><a class="btn" href="/profile.html" style="display:inline-block;margin-top:14px;text-decoration:none">Manage Profile</a></div><div class="panel"><div class="eyebrow">AVX WALLET</div><h2>Wallet</h2><div id="walletBox" class="identity-card">Loading...</div><a class="btn ghost" href="/wallet.html" style="display:inline-block;margin-top:14px;text-decoration:none">Open Wallet</a></div></section><section class="dash-message"><div><div class="eyebrow">THE AVELYX PROMISE</div><h2>Prove Your Potential.</h2><p>Build it. Verify it. Share it. Let your professional identity speak for you.</p></div><a href="/profile.html" class="btn">Continue Building</a></section>`,`<style>.dash-hero{display:flex;justify-content:space-between;align-items:center;gap:30px;padding:34px;border-radius:28px;border:1px solid rgba(139,77,255,.3);background:radial-gradient(circle at 82% 25%,rgba(139,77,255,.26),transparent 28%),linear-gradient(135deg,#080d22,#111a3b 60%,#0c1027);box-shadow:0 25px 70px rgba(0,0,0,.22)}.dash-copy{max-width:700px}.dash-copy h1{font-size:clamp(34px,5vw,58px);margin:9px 0 12px;letter-spacing:-1.8px}.dash-copy p{max-width:650px;color:#b9c4e8;line-height:1.7;margin:0}.dash-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}.dash-mark{width:170px;height:170px;flex:0 0 170px;display:grid;place-items:center;position:relative}.mark-orbit{position:absolute;inset:7px;border:1px dashed rgba(181,159,255,.65);border-radius:50%;animation:spin 13s linear infinite}.mark-orbit:before,.mark-orbit:after{content:'';position:absolute;width:9px;height:9px;border-radius:50%;background:#a98cff;box-shadow:0 0 18px #a98cff}.mark-orbit:before{top:7px;left:50%}.mark-orbit:after{bottom:18px;right:5px}.mark-core{width:118px;height:118px;border-radius:34% 34% 42% 42%;display:grid;place-items:center;background:linear-gradient(145deg,#f4f2f7 0%,#c9c7cf 42%,#8f8d97 100%);color:#17142a;position:relative;box-shadow:0 0 0 5px rgba(212,174,74,.18),0 0 38px rgba(139,77,255,.55),inset 0 1px 0 rgba(255,255,255,.9);animation:pulse 3s ease-in-out infinite;overflow:visible}.mark-core:before{content:'';position:absolute;inset:-10px;border-radius:40%;background:linear-gradient(135deg,rgba(139,77,255,.65),rgba(212,174,74,.32),rgba(139,77,255,.12));filter:blur(13px);z-index:-1}.verify-letter{font-size:64px;font-weight:1000;font-style:italic;line-height:1;text-shadow:0 3px 8px rgba(255,255,255,.45),0 4px 10px rgba(38,24,75,.25)}.verify-crown{position:absolute;top:-29px;left:50%;transform:translateX(-50%);font-size:42px;line-height:1;color:#d4ae4a;text-shadow:0 2px 0 #8b6d24,0 0 18px rgba(212,174,74,.75);font-style:normal}.verify-badge{position:absolute;right:-8px;bottom:-7px;width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#8b4dff,#5d36c9);color:#fff;border:3px solid #f1eef5;font-size:18px;font-weight:1000;box-shadow:0 0 20px rgba(139,77,255,.65)}.dash-mark small{position:absolute;bottom:-7px;font-size:9px;letter-spacing:2px;color:#dce3ff;background:#111936;border:1px solid rgba(255,255,255,.12);padding:7px 10px;border-radius:999px}.dash-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}.dash-tile{position:relative;min-height:145px;padding:21px;border:1px solid rgba(105,120,185,.22);border-radius:20px;background:linear-gradient(145deg,#0b122a,#080d20);color:#fff;text-decoration:none;transition:.18s;overflow:hidden}.dash-tile:hover{transform:translateY(-3px);border-color:rgba(139,77,255,.55)}.dash-tile.featured{background:linear-gradient(145deg,rgba(139,77,255,.18),#0b122a 65%);border-color:rgba(139,77,255,.4)}.dash-tile span:first-child{font-size:10px;letter-spacing:1.5px;color:#8d9ac1;font-weight:900}.dash-tile b{display:block;font-size:17px;margin:12px 0 7px}.dash-tile small{display:block;color:#9eabd0;line-height:1.55}.badge{position:absolute;right:14px;top:14px;min-width:24px;height:24px;border-radius:999px;background:#ff477e;text-align:center;line-height:24px;font-size:11px;font-weight:900}.dash-bottom{margin-top:18px}.identity-card{padding:18px;border:1px solid rgba(105,120,185,.24);border-radius:16px;background:linear-gradient(145deg,#080e23,#0c1430)}.dash-message{margin-top:18px;padding:24px;border-radius:22px;border:1px solid rgba(212,174,74,.24);background:linear-gradient(110deg,rgba(139,77,255,.12),rgba(212,174,74,.08));display:flex;align-items:center;justify-content:space-between;gap:20px}.dash-message h2{margin:5px 0}.dash-message p{margin:0;color:#aeb9dc}.dash-message .btn{white-space:nowrap}@media(max-width:800px){.dash-hero{flex-direction:column;align-items:flex-start}.dash-mark{align-self:center}.dash-grid{grid-template-columns:1fr 1fr}.dash-message{flex-direction:column;align-items:flex-start}}@media(max-width:520px){.dash-grid{grid-template-columns:1fr}.dash-copy h1{font-size:35px}}@media(prefers-reduced-motion:reduce){.mark-orbit,.mark-core{animation:none}}</style>`+memberGuardScript()+`<script>(async()=>{const p=await me();if(!p)return;document.getElementById('welcome').textContent='Welcome, '+p.full_name;document.getElementById('identityBox').innerHTML='<b>'+esc(p.avx_id)+'</b><br><span class="pill">'+esc((p.account_type||'individual').toUpperCase())+'</span> · '+esc((p.card_tier||'basic').toUpperCase())+'<br><small class="muted">'+esc(p.title||'Professional identity')+'</small>';document.getElementById('walletBox').innerHTML='<b style="font-size:24px">'+Number(p.avx_balance||0).toLocaleString()+' AVX</b><br><small class="muted">Your AVX wallet</small>';try{const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();const n=(d.requests||[]).filter(x=>x.status==='pending').length;if(n){document.getElementById('notificationBadge').style.display='block';document.getElementById('notificationBadge').textContent=n}}catch(e){}})()</script>`)}
function profilePage(){return shell('My Profile',`<section class="profile-hero"><div class="profile-glow"></div><div class="verify-orbit" aria-label="AVELYX Verification"><div class="orbit-ring"></div><div class="verify-core"><span class="verify-a">A</span><span class="verify-check">✓</span></div><div class="orbit-label">AVELYX VERIFIED</div></div><div class="profile-hero-copy"><div class="eyebrow">MY PROFILE</div><h1>Professional Identity</h1><p>Build a profile people can trust. Keep your information complete, request verification and use one AVELYX identity everywhere.</p><div class="profile-mini-badges"><span>✦ Secure Identity</span><span>◉ Shareable QR</span><span>✓ Permission Controlled</span></div></div></section>
<section class="panel card-panel" style="margin-top:18px"><div class="eyebrow">YOUR AVELYX CARD</div><div class="card-head"><div><h2 id="cardTitle">AVELYX Card</h2><p id="cardSubtitle" class="muted">Your account level determines the card available to you.</p></div><span id="cardEligibility" class="pill">Loading card status…</span></div><div class="member-card-wrap"><img id="memberCardImage" class="member-card-image" src="/avelix-basic-card.png" alt="AVELYX Card"><div class="card-purchase"><button id="purchaseCardBtn" class="btn" onclick="purchaseCard()" disabled>Purchase Card</button><div id="purchaseMsg" class="muted" style="margin-top:10px"></div><a id="verifyLink" href="#verificationCenter" class="verify-link" style="display:none">Verify all documents</a></div></div></section>
<section id="verificationCenter" class="panel verification-panel" style="margin-top:18px"><div class="section-head"><div><div class="eyebrow">VERIFICATION CENTER</div><h2>Verify Your Professional Identity</h2><p class="muted">Request verification for the information that matters. AVELYX will show a clear status for each request.</p></div><span class="pill">SECURE</span></div><div id="verificationList" class="verification-grid"><div class="loading-card"><span class="spinner"></span> Loading verification status…</div></div><div id="verificationMsg"></div></section>
<section class="profile-layout"><div class="panel profile-panel"><div class="section-head"><div><div class="eyebrow">IDENTITY DETAILS</div><h2>Profile Information</h2><p class="muted">Complete your details to improve your profile and card eligibility.</p></div><div class="live-dot"><i></i> LIVE</div></div><div id="profileForm"><div class="loading-card"><span class="spinner"></span> Loading your profile…</div></div></div><div class="panel level-panel"><div class="eyebrow">AVELYX STATUS</div><h2>Profile Level</h2><div id="levelBox"><div class="loading-card"><span class="spinner"></span> Loading your level…</div></div><div id="upgradeBox" style="margin-top:16px"></div><div class="level-road"><div class="road-title">YOUR JOURNEY</div><div class="road-step" id="roadIndividual"><b>01</b><span>Basic Individual</span></div><div class="road-step" id="roadEntrepreneur"><b>02</b><span>Platinum Professional</span></div><div class="road-step" id="roadBusiness"><b>03</b><span>Gold Business</span></div></div></div></section>`,`<style>.profile-hero{position:relative;overflow:hidden;display:flex;align-items:center;gap:30px;padding:34px;border-radius:26px;border:1px solid rgba(100,120,220,.35);background:radial-gradient(circle at 82% 35%,rgba(103,80,255,.35),transparent 30%),linear-gradient(135deg,#080d22,#111a3b 55%,#0b1028);box-shadow:0 22px 60px rgba(0,0,0,.25);min-height:260px}.profile-glow{position:absolute;width:240px;height:240px;border-radius:50%;right:-80px;top:-80px;background:rgba(110,92,255,.18);filter:blur(10px)}.profile-hero-copy{position:relative;z-index:2;max-width:680px}.profile-hero h1{margin:6px 0 10px;font-size:clamp(32px,5vw,52px);letter-spacing:-1.5px}.profile-hero p{margin:0;color:#b9c4e8;line-height:1.65;font-size:15px}.profile-mini-badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.profile-mini-badges span{padding:8px 11px;border:1px solid rgba(255,255,255,.12);border-radius:999px;background:rgba(255,255,255,.05);font-size:11px;font-weight:800;color:#dce4ff}.verify-orbit{position:relative;width:170px;height:170px;flex:0 0 170px;display:grid;place-items:center}.orbit-ring{position:absolute;inset:4px;border-radius:50%;border:1px dashed rgba(152,165,255,.7);animation:spin 13s linear infinite}.orbit-ring:before,.orbit-ring:after{content:'';position:absolute;width:9px;height:9px;border-radius:50%;background:#8b7cff;box-shadow:0 0 18px #8b7cff}.orbit-ring:before{top:10px;left:50%}.orbit-ring:after{bottom:18px;right:10px}.verify-core{width:112px;height:112px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#fff,#cbd4ff);color:#10152e;box-shadow:0 0 0 8px rgba(255,255,255,.06),0 0 42px rgba(123,103,255,.5);position:relative;animation:pulse 3s ease-in-out infinite}.verify-a{font-size:54px;font-weight:1000;font-style:italic;line-height:1}.verify-check{position:absolute;right:8px;bottom:7px;width:31px;height:31px;border-radius:50%;display:grid;place-items:center;background:#151d48;color:white;font-size:19px;font-weight:1000;border:3px solid #fff}.orbit-label{position:absolute;bottom:-4px;white-space:nowrap;font-size:9px;font-weight:1000;letter-spacing:2px;color:#dce3ff;background:#111936;padding:7px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.14)}.profile-layout{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(280px,.8fr);gap:16px;margin-top:18px;align-items:start}.profile-panel,.level-panel,.verification-panel{border-color:rgba(91,110,190,.28);box-shadow:0 12px 35px rgba(0,0,0,.12)}.section-head{display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.section-head h2{margin:3px 0}.live-dot{font-size:10px;font-weight:900;letter-spacing:1px;color:#b9c6ff;padding:7px 10px;border-radius:999px;background:rgba(88,105,200,.12)}.live-dot i{display:inline-block;width:7px;height:7px;border-radius:50%;background:#72e6a4;margin-right:5px;box-shadow:0 0 10px #72e6a4}.loading-card{display:flex;align-items:center;gap:10px;padding:18px;border:1px dashed rgba(125,140,205,.3);border-radius:15px;color:#aeb9dc;background:rgba(255,255,255,.025)}.spinner{width:16px;height:16px;border-radius:50%;border:2px solid rgba(255,255,255,.2);border-top-color:#9d91ff;animation:spin .8s linear infinite}.level-panel{background:linear-gradient(160deg,#0b112b,#10183a)}.level-road{margin-top:22px;padding-top:18px;border-top:1px solid rgba(255,255,255,.08)}.road-title{font-size:10px;font-weight:900;letter-spacing:1.5px;color:#8491ba;margin-bottom:12px}.road-step{display:flex;align-items:center;gap:10px;padding:9px 0;color:#7f8caf;font-size:12px}.road-step b{width:27px;height:27px;border-radius:50%;display:grid;place-items:center;border:1px solid rgba(255,255,255,.12);font-size:9px}.road-step.active{color:#e5e9ff}.road-step.active b{background:#7264ff;color:white;border-color:#7264ff;box-shadow:0 0 18px rgba(114,100,255,.4)}.member-card-wrap{display:flex;flex-direction:column;align-items:center;gap:16px;margin-top:18px;min-width:0}.member-card-image{display:block;width:min(100%,520px);height:auto;max-height:310px;object-fit:contain;border-radius:18px;border:1px solid #29365c;box-shadow:0 20px 50px #0008}.card-purchase{width:100%;text-align:center}.card-purchase .btn{min-width:190px}.verify-link{display:inline-block;margin-top:10px;color:#d5c9ff;font-weight:800;text-decoration:none}.verification-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:16px}.verification-item{padding:16px;border:1px solid #202c50;border-radius:16px;background:linear-gradient(145deg,#0a1026,#0d1530)}.verification-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.verification-item h3{margin:0;font-size:15px}.verification-item p{margin:9px 0;color:#98a6c8;font-size:12px;line-height:1.5}.verify-status{font-size:9px;font-weight:900;letter-spacing:.1em;padding:6px 8px;border-radius:999px;background:#111b3b;color:#aebbe0}.verify-status.verified{color:#7ce5aa;background:#0e2a20}.verify-status.pending{color:#ffd078;background:#2b2110}.verify-status.rejected{color:#ff91a5;background:#2c101a}.verify-action{border:1px solid #34426b;background:#111a36;color:white;border-radius:10px;padding:9px 12px;font-weight:800;cursor:pointer}.verify-action:disabled{opacity:.45;cursor:not-allowed}@keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.035)}}@media(max-width:800px){.profile-hero{padding:25px;flex-direction:column;align-items:flex-start}.verify-orbit{width:140px;height:140px;flex-basis:140px}.verify-core{width:92px;height:92px}.verify-a{font-size:44px}.profile-layout{grid-template-columns:1fr}.verification-grid{grid-template-columns:1fr}.member-card-image{width:100%;max-width:420px;max-height:240px}.card-panel{overflow:hidden}}@media(prefers-reduced-motion:reduce){.orbit-ring,.verify-core{animation:none}}</style>`+memberGuardScript()+`<script>let profile;const labels={individual:'Basic — Individual',entrepreneur:'Platinum — Entrepreneur / Professional',business:'Gold — Business / Organization'};const VERIFY_TYPES=[['identity','Identity','Confirm your identity information.'],['education','Education','Confirm degrees, diplomas and academic qualifications.'],['employment','Employment','Confirm employment or professional experience.'],['certification','Certification','Confirm professional certificates and licences.'],['business','Business / CAC','Confirm business registration details.']];async function loadMyProfile(){const box=document.getElementById('profileForm');try{const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store',signal:controller.signal});clearTimeout(timer);const d=await r.json().catch(()=>({}));if(!r.ok||!d.profile){box.innerHTML='<div class="error">Your profile could not be loaded. Please log in again.</div>';document.getElementById('levelBox').innerHTML='<div class="error">Profile level unavailable.</div>';return false}profile=d.profile;box.innerHTML=formHtml(profile);renderLevel();setBaseCard(profile);return true}catch(e){console.error('AVELYX profile load',e);box.innerHTML='<div class="error">Profile loading failed. Refresh the page or log in again.</div>';document.getElementById('levelBox').innerHTML='<div class="error">Profile level could not be loaded.</div>';return false}}function formHtml(p){return '<div class="field"><b>'+esc(p.avx_id)+'</b><br><small class="muted">Your permanent AVELYX ID</small></div><label>Full name *</label><input id="full_name" value="'+attr(p.full_name)+'"><label>Professional title</label><input id="title" value="'+attr(p.title)+'"><label>Organization / business</label><input id="organization" value="'+attr(p.organization)+'"><label>Industry</label><input id="industry" value="'+attr(p.industry)+'"><label>Location</label><input id="location" value="'+attr(p.location)+'"><label>Phone</label><input id="phone" value="'+attr(p.phone)+'"><label>Website</label><input id="website" value="'+attr(p.website)+'"><label>CAC / RC number</label><input id="cac_number" value="'+attr(p.cac_number)+'"><label>Skills</label><input id="skills" value="'+attr(p.skills)+'" placeholder="Python, CAD, marketing..."><label>Qualifications</label><textarea id="qualifications">'+esc(p.qualifications)+'</textarea><label>Certifications</label><textarea id="certifications">'+esc(p.certifications)+'</textarea><label>About</label><textarea id="bio">'+esc(p.bio)+'</textarea><button class="btn" style="margin-top:14px" onclick="saveProfile()">Save Changes</button><div id="msg"></div>'}function renderLevel(){const levelBox=document.getElementById('levelBox'),upgradeBox=document.getElementById('upgradeBox');const t=profile.account_type||'individual';levelBox.innerHTML='<span class="pill">'+esc(labels[t]||labels.individual)+'</span><div class="field" style="margin-top:14px"><b>AVELYX ID</b><br>'+esc(profile.avx_id)+'<br><b style="display:block;margin-top:10px">Card Tier</b>'+esc((profile.card_tier||'basic').toUpperCase())+'</div>';['roadIndividual','roadEntrepreneur','roadBusiness'].forEach(x=>document.getElementById(x).classList.remove('active'));document.getElementById(t==='business'?'roadBusiness':t==='entrepreneur'?'roadEntrepreneur':'roadIndividual').classList.add('active');if(t==='individual')upgradeBox.innerHTML='<p class="muted">Your Basic Individual identity is active.</p><button class="btn" onclick="upgrade(\'entrepreneur\')">Upgrade to Platinum</button>';else if(t==='entrepreneur')upgradeBox.innerHTML='<span class="pill">PLATINUM ACTIVE</span><p class="muted">Your professional identity is at Platinum level.</p><button class="btn" onclick="upgrade(\'business\')">Upgrade to Gold Business</button>';else upgradeBox.innerHTML='<span class="pill">GOLD BUSINESS ACTIVE</span><p class="muted">Your business identity is at Gold level.</p>'}function setBaseCard(p){const names={basic:'Basic Card',platinum:'Platinum Card',gold:'Gold Card'},files={basic:'/avelix-basic-card.png',platinum:'/avelix-platinum-card.png',gold:'/avelix-gold-card.png'};const tier=p.card_tier||(p.account_type==='business'?'gold':p.account_type==='entrepreneur'?'platinum':'basic');document.getElementById('cardTitle').textContent=names[tier]||'AVELYX Card';document.getElementById('memberCardImage').src=files[tier]||files.basic;document.getElementById('cardEligibility').textContent='Checking verification…';document.getElementById('purchaseCardBtn').disabled=true}async function saveProfile(){const r=await fetch('/api/profile',{method:'PUT',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({full_name:document.getElementById('full_name').value,email:profile.login_email||profile.email,title:document.getElementById('title').value,organization:document.getElementById('organization').value,industry:document.getElementById('industry').value,location:document.getElementById('location').value,phone:document.getElementById('phone').value,website:document.getElementById('website').value,cac_number:document.getElementById('cac_number').value,skills:document.getElementById('skills').value,qualifications:document.getElementById('qualifications').value,certifications:document.getElementById('certifications').value,bio:document.getElementById('bio').value})});const d=await r.json().catch(()=>({}));const msg=document.getElementById('msg');msg.className=r.ok?'toast':'error';msg.textContent=r.ok?'Profile saved successfully.':(d.error||'Unable to save profile.');if(r.ok)await loadMyProfile()}async function upgrade(target){let body={target_type:target};if(target==='business'){body.organization=prompt('Business / organization name:',profile.organization||'');if(!body.organization)return;body.industry=prompt('Industry:',profile.industry||'')||profile.industry;body.cac_number=prompt('CAC / RC number:',profile.cac_number||'')||profile.cac_number}const r=await fetch('/api/profile/upgrade',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));if(!r.ok){alert(d.error||'Unable to upgrade');return}profile=Object.assign({},profile,{account_type:d.account_type,card_tier:d.card_tier});renderLevel();setBaseCard(profile);loadCard()}function statusClass(s){return String(s||'pending').toLowerCase()}function renderVerification(requests,credentials){const list=document.getElementById('verificationList');const byType={};(requests||[]).forEach(x=>{const k=String(x.verification_type||'').toLowerCase();if(!byType[k]||Number(x.id)>Number(byType[k].id))byType[k]=x});const verifiedTypes=new Set((credentials||[]).filter(c=>String(c.status).toLowerCase()==='verified').map(c=>String(c.credential_type||'').toLowerCase()));list.innerHTML=VERIFY_TYPES.map(([type,title,desc])=>{const req=byType[type];let state=req?String(req.status||'pending').toLowerCase():(verifiedTypes.has(type)?'verified':'not submitted');let label=state==='accepted'?'PENDING':state.toUpperCase();if(state==='not submitted')label='NOT SUBMITTED';const disabled=['pending','accepted','verified'].includes(state);return '<div class="verification-item"><div class="verification-top"><h3>'+esc(title)+'</h3><span class="verify-status '+statusClass(state)+'">'+esc(label)+'</span></div><p>'+esc(desc)+'</p>'+(state==='verified'?'<small class="muted">Verified evidence is recorded on your AVELYX profile.</small>':'<button class="verify-action" '+(disabled?'disabled':'')+' onclick="startVerification(\''+type+'\')">'+(state==='rejected'?'Request Again':'Start Verification')+'</button>')+'</div>'}).join('')}async function loadVerification(){const list=document.getElementById('verificationList');try{const [rr,cr]=await Promise.all([fetch('/api/verification/requests',{credentials:'same-origin',cache:'no-store'}),fetch('/api/credentials',{credentials:'same-origin',cache:'no-store'})]);const rd=await rr.json().catch(()=>({requests:[]}));const cd=await cr.json().catch(()=>({credentials:[]}));renderVerification(rd.requests||[],cd.credentials||[])}catch(e){console.error(e);list.innerHTML='<div class="error">Verification status could not be loaded.</div>'}}async function startVerification(type){const evidence=prompt('Enter the key information or reference AVELYX should use for this verification. Do not enter passwords or sensitive secrets.');if(evidence===null)return;const r=await fetch('/api/verification/requests',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({verification_type:type,evidence:evidence.trim()})});const d=await r.json().catch(()=>({}));const msg=document.getElementById('verificationMsg');msg.className=r.ok?'toast':'error';msg.textContent=d.message||d.error||'Unable to start verification.';if(r.ok)loadVerification()}async function loadCard(){const badge=document.getElementById('cardEligibility'),btn=document.getElementById('purchaseCardBtn'),link=document.getElementById('verifyLink'),msg=document.getElementById('purchaseMsg');try{const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);const r=await fetch('/api/card/status',{credentials:'same-origin',cache:'no-store',signal:controller.signal});clearTimeout(timer);const d=await r.json().catch(()=>({}));const names={basic:'Basic Card',platinum:'Platinum Card',gold:'Gold Card'};const tier=d.card_tier||profile.card_tier||(profile.account_type==='business'?'gold':profile.account_type==='entrepreneur'?'platinum':'basic');const files={basic:'/avelix-basic-card.png',platinum:'/avelix-platinum-card.png',gold:'/avelix-gold-card.png'};document.getElementById('cardTitle').textContent=names[tier]||'AVELYX Card';document.getElementById('memberCardImage').src=files[tier]||files.basic;if(!r.ok){badge.textContent='VERIFICATION STATUS UNAVAILABLE';badge.style.color='#ffbd68';btn.disabled=true;msg.textContent='Complete verification in the Verification Center before purchasing a card.';link.style.display='inline-block';link.href='#verificationCenter';return}if(d.eligible){badge.textContent='ELIGIBLE';badge.style.color='#73e4a4';btn.disabled=false;btn.textContent='Purchase '+(names[tier]||'Card');link.style.display='none';msg.textContent='Your required profile information and verification are complete.'}else{badge.textContent='VERIFICATION REQUIRED';badge.style.color='#ffbd68';btn.disabled=true;btn.textContent='Purchase Card';link.style.display='inline-block';link.href='#verificationCenter';msg.textContent='Complete the required profile information and verification before purchasing this card.';const missing=(d.missing||[]).slice(0,5);if(missing.length)msg.textContent+=' Missing: '+missing.join(', ')}}catch(e){badge.textContent='VERIFICATION STATUS UNAVAILABLE';badge.style.color='#ffbd68';btn.disabled=true;msg.textContent='Complete verification in the Verification Center before purchasing a card.';link.style.display='inline-block';link.href='#verificationCenter'}}async function purchaseCard(){const btn=document.getElementById('purchaseCardBtn'),msg=document.getElementById('purchaseMsg');btn.disabled=true;const r=await fetch('/api/card/purchase',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:'{}'});const d=await r.json().catch(()=>({}));msg.className=r.ok?'toast':'error';msg.textContent=r.ok?(d.message+' Reference: '+d.reference):((d.error||'Unable to purchase card.')+(d.missing?.length?' Missing: '+d.missing.join(', '):''));if(r.ok)btn.textContent='Order Created';else btn.disabled=false}(async()=>{const ok=await loadMyProfile();if(ok){await Promise.all([loadVerification(),loadCard()])}})()</script>`)}
function qrPage(){return shell('Secure QR',`<section class="hero"><div class="eyebrow">SECURE SHARING</div><h1>One-scan AVELYX QR</h1><p class="muted">Generate a temporary link that expires after 30 minutes or one successful scan.</p></section><section class="panel center"><div id="qr" class="qr"></div><div id="qrmsg" class="muted">Tap the button to generate your secure QR.</div><button class="btn" style="margin-top:16px" onclick="generateQR()">Generate Secure QR</button><a class="btn ghost" href="/dashboard.html" style="display:inline-block;margin-top:10px;text-decoration:none">Back to Dashboard</a></section>`,`<style>.center{text-align:center}.qr{min-height:20px}.qr canvas,.qr img{max-width:280px;margin:18px auto;display:block;background:white;padding:10px;border-radius:16px}</style>`+memberGuardScript()+`<script>let qrReady=false;async function loadQrLib(){if(typeof QRCode!=='undefined')return true;return new Promise(resolve=>{const s=document.createElement('script');s.src='https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';s.onload=()=>resolve(true);s.onerror=()=>resolve(false);document.head.appendChild(s)})}async function generateQR(){const p=await me();if(!p)return;const r=await fetch('/api/share',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({fields:['full_name','title','organization','industry','location','website','bio']})});const d=await r.json();if(!r.ok){qrmsg.className='error';qrmsg.textContent=d.error||'QR generation failed.';return}qr.innerHTML='';const loaded=await loadQrLib();if(loaded){new QRCode(qr,{text:d.url,width:240,height:240});}else{const img=document.createElement('img');img.alt='Secure AVELYX QR';img.src='https://api.qrserver.com/v1/create-qr-code/?size=240x240&data='+encodeURIComponent(d.url);qr.appendChild(img)}qrmsg.innerHTML='<b>ONE SCAN ONLY</b><br>Expires: '+new Date(d.expires_at*1000).toLocaleString()+'<br><span class="share-url">'+esc(d.url)+'</span>'}</script>`)}
function permissionsPage(){return shell('Information Permissions',`<section class="hero"><div class="eyebrow">CONSENT & PRIVACY</div><h1>Information Permissions</h1><p class="muted">Choose exactly what another AVELYX member may access. Nothing is approved automatically.</p></section><section class="grid"><div class="panel"><h2>Requests Received</h2><div id="received">Loading...</div></div><div class="panel"><h2>Request Information</h2><p class="muted">Enter an AVELYX ID and select only the information you need.</p><input id="avxId" placeholder="AVELYX ID"><div id="checks" class="checks">${['full_name','title','organization','industry','location','website','bio','phone','skills','qualifications','certifications','cac_number'].map(f=>`<label class="check"><input type="checkbox" value="${f}"> ${PERMISSION_LABELS[f]||f}</label>`).join('')}</div><textarea id="reason" placeholder="Reason for requesting this information"></textarea><button class="btn" style="margin-top:12px" onclick="requestInfo()">Send Request</button><div id="sentMsg"></div></div></section>`,`<style>.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.check{margin:0;padding:10px;border:1px solid var(--line);border-radius:10px;background:#070c1d}.check input{width:auto;margin-right:7px}.request{margin-bottom:10px}.actions{display:flex;gap:8px;flex-wrap:wrap}@media(max-width:650px){.checks{grid-template-columns:1fr}}</style>`+memberGuardScript()+`<script>const PL={full_name:'Full name',title:'Professional title',organization:'Organization',industry:'Industry',location:'Location',website:'Website',bio:'About',phone:'Phone',skills:'Skills',qualifications:'Qualifications',certifications:'Certifications',cac_number:'CAC / RC number'};function fields(a){return (a||[]).map(x=>'<span class="pill" style="margin:2px">'+esc(PL[x]||x)+'</span>').join('')}async function loadRequests(){const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();if(!r.ok){received.innerHTML='<p class="error">'+esc(d.error||'Unable to load requests')+'</p>';return}received.innerHTML=(d.requests||[]).map(x=>'<div class="field request"><b>'+esc(x.requester_name||'AVELYX member')+'</b><br><small>'+esc(x.requester_email||'')+'</small><p>'+fields(x.requested_fields)+'</p><small class="muted">'+esc(x.reason||'No reason provided')+'</small><br><span class="pill">'+esc(String(x.status).toUpperCase())+'</span>'+(x.status==='pending'?'<div class="actions" style="margin-top:10px"><button class="btn" onclick="respond('+x.id+',true)">Accept</button><button class="btn ghost" onclick="respond('+x.id+',false)">Decline</button></div>':'')+'</div>').join('')||'<p class="muted">No requests yet.</p>'}async function respond(id,yes){let approved=[];if(yes){const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();const row=(d.requests||[]).find(x=>x.id===id);approved=(row?.requested_fields||[]).filter(f=>confirm('Approve access to '+(PL[f]||f)+'?'));if(!approved.length)return alert('No information was approved.')}const r=await fetch('/api/information-requests/'+id+'/respond',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decision:yes?'accepted':'declined',approved_fields:approved})});const d=await r.json();if(!r.ok)return alert(d.error||'Unable to respond');loadRequests()}async function requestInfo(){const id=avxId.value.trim();const fs=[...document.querySelectorAll('#checks input:checked')].map(x=>x.value);if(!id||!fs.length){sentMsg.className='error';sentMsg.textContent='Enter an AVELYX ID and select at least one field.';return}const r=await fetch('/api/information-requests',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({avx_id:id,requested_fields:fs,reason:reason.value.trim()})});const d=await r.json();sentMsg.className=r.ok?'toast':'error';sentMsg.textContent=d.message||d.error;if(r.ok){avxId.value='';reason.value='';document.querySelectorAll('#checks input').forEach(x=>x.checked=false)}}(async()=>{if(await me())loadRequests()})()</script>`)}
function notificationsPage(){return shell('Notifications',`<section class="hero"><div class="eyebrow">NOTIFICATIONS</div><h1>Your Notifications</h1><p class="muted">Important account activity appears here. Permission requests can be reviewed from the Information Permissions page.</p></section><section class="panel"><div id="noticeList">Loading...</div><a class="btn" href="/permissions.html" style="display:inline-block;margin-top:14px;text-decoration:none">Open Information Permissions</a></section>`,`<style>.notice{display:flex;gap:14px;align-items:flex-start;padding:16px;border:1px solid var(--line);border-radius:16px;background:#070c1d;margin-bottom:10px}.notice-icon{font-size:22px}</style>`+memberGuardScript()+`<script>(async()=>{const p=await me();if(!p)return;const r=await fetch('/api/information-requests',{credentials:'same-origin'});const d=await r.json();const pending=(d.requests||[]).filter(x=>x.status==='pending');noticeList.innerHTML=pending.map(x=>'<div class="notice"><div class="notice-icon">🔔</div><div><b>Information request from '+esc(x.requester_name||'AVELYX member')+'</b><p class="muted">They are requesting selected information from your profile.</p><span class="pill">ACTION REQUIRED</span></div></div>').join('')||'<div class="field"><b>No new notifications</b><p class="muted">You are all caught up.</p></div>'})()</script>`)}
function walletPage(){return shell('AVX Wallet',`<section class="hero"><div class="eyebrow">AVX WALLET</div><h1>Your Wallet</h1><p class="muted">Your AVX balance is visible. Wallet actions remain locked until the AVELYX verification economy launches.</p></section><section class="panel"><div class="field"><small class="muted">CURRENT BALANCE</small><div id="balance" style="font-size:42px;font-weight:900;margin-top:8px">0 AVX</div></div><p class="muted">Receiving, sending and buying AVX are currently locked in the MVP.</p><span class="pill">USE LOCKED</span></section>`,`<style>.field{margin-top:8px}</style>`+memberGuardScript()+`<script>(async()=>{const p=await me();if(p)balance.textContent=Number(p.avx_balance||0).toLocaleString()+' AVX'})()</script>`)}
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

async function myCredentials(request, env) {
  await ensureCredentialsTable(env);
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
  await ensureCredentialsTable(env);
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const rows=await env.DB.prepare(`SELECT c.*, p.full_name, p.avx_id, p.account_type FROM credentials c JOIN profiles p ON p.id=c.profile_id ORDER BY c.created_at DESC`).all();
  return json({credentials:rows.results||[]});
}
async function adminCreateCredential(request, env) {
  await ensureCredentialsTable(env);
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
  await ensureCredentialsTable(env);
  const admin=await requireAdmin(request,env); if(!admin) return adminDenied();
  const b=await request.json(); const id=String(b.credential_id||'').trim(); const status=String(b.status||'');
  if(!['pending','verified','expired','revoked','unverified'].includes(status)) return json({error:'Invalid credential status.'},400);
  const row=await env.DB.prepare('SELECT * FROM credentials WHERE credential_id=?').bind(id).first(); if(!row) return json({error:'Credential not found.'},404);
  await env.DB.prepare('UPDATE credentials SET status=?, verified_at=? WHERE credential_id=?').bind(status,status==='verified'?now():null,id).run();
  await env.DB.prepare('INSERT INTO audit_logs (actor_user_id,action,target_type,target_id,details) VALUES (?,?,?,?,?)').bind(admin.user_id,'credential.status','credential',id,JSON.stringify({from:row.status,to:status})).run();
  return json({ok:true});
}
async function publicCredential(request, env, id) {
  await ensureCredentialsTable(env);
  const c=await env.DB.prepare(`SELECT c.*,p.full_name,p.avx_id,p.organization,p.title AS profile_title FROM credentials c JOIN profiles p ON p.id=c.profile_id WHERE c.credential_id=?`).bind(id).first();
  if(!c) return new Response('Credential not found',{status:404});
  const status=c.status==='verified'?'VERIFIED':String(c.status||'UNVERIFIED').toUpperCase();
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(c.title)} • AVELYX</title>${styles()}</head><body><main class="public"><div class="brand">AVELYX<span>◆</span></div><section class="profile-card"><div class="eyebrow">AVELYX VERIFIED CREDENTIAL</div><h1>${esc(c.title)}</h1><p class="sub">${esc(c.full_name)}${c.organization?' · '+esc(c.organization):''}</p><div class="status ${c.status==='verified'?'':'bad'}">● ${esc(status)}</div><div class="fields"><div class="field"><span>Credential Type</span><strong>${esc(c.credential_type)}</strong></div><div class="field"><span>Issuer</span><strong>${esc(c.issuer||'Not provided')}</strong></div><div class="field"><span>Credential ID</span><strong>${esc(c.credential_id)}</strong></div><div class="field"><span>Verification Date</span><strong>${c.verified_at?new Date(c.verified_at*1000).toLocaleString():'Not yet verified'}</strong></div></div><div class="idbox"><small>AVELYX PROFILE</small><b>${esc(c.avx_id)}</b></div><p class="foot">Status reflects the current AVELYX verification record.</p></section></main></body></html>`,{headers:{'content-type':'text/html;charset=UTF-8'}});
}
function adminPage(){return shell('AVELYX Admin Control Center',`<section class="hero"><div class="eyebrow">AVELYX ADMIN</div><h1>Platform Control Center</h1><p class="muted">Control AVX, packages, feature launches, job listings, wallet credits and credential verification without changing or redeploying the website.</p></section><section class="panel"><h2>Feature Launch Controls</h2><div id="settings" class="grid"></div></section><section class="grid" style="margin-top:16px"><div class="panel"><h2>AVX Package Manager</h2><div class="grid"><div><label>Package name</label><input id="pname" placeholder="Starter"></div><div><label>Price (NGN)</label><input id="pprice" type="number" placeholder="5000"></div><div><label>AVX amount</label><input id="pamount" type="number" placeholder="50"></div><div><label>Sort order</label><input id="psort" type="number" value="0"></div><div class="wide"><label>Description</label><input id="pdesc" placeholder="AVX credit package"></div><div><label>Active</label><select id="pactive"><option value="1">Yes</option><option value="0">No</option></select></div></div><button class="btn" style="margin-top:14px" onclick="savePackage()">Create Package</button><div id="packages" style="margin-top:16px"></div></div><div class="panel"><h2>AVX Treasury</h2><div id="treasuryBox" class="field">Loading treasury...</div><p class="muted">The initial 1,000,000,000 AVX reserve is held in the admin treasury. Member wallets are opened for AVX balances, but member use remains locked until verification launches.</p><label>Unlock amount later</label><input id="unlockAmount" type="number" placeholder="e.g. 1000000"><button class="btn ghost" style="margin-top:10px" onclick="unlockTreasury()">Unlock Supply</button><div id="treasuryMsg"></div></div><div class="panel"><h2>Credit AVX to Member</h2><label>Member AVELYX ID</label><input id="wavx" placeholder="AVX-..."><label>Amount</label><input id="wamount" type="number" placeholder="100"><label>Payment/reference</label><input id="wref" placeholder="Payment reference"><label>Note</label><input id="wnote" placeholder="Manual credit after payment confirmation"><button class="btn" style="margin-top:14px" onclick="creditWallet()">Credit Wallet</button><div id="walletMsg"></div><div id="members" style="margin-top:16px"></div></div></section><section class="panel" style="margin-top:16px"><h2>Job Listings Manager</h2><p class="muted">Add or maintain opportunities used by the AVELYX qualification matching engine.</p><div class="grid"><div><label>Job title</label><input id="jtitle" placeholder="Software Developer"></div><div><label>Employer</label><input id="jemployer" placeholder="Company name"></div><div><label>Location</label><input id="jlocation" placeholder="Kaduna / Remote"></div><div><label>Work mode</label><input id="jmode" placeholder="Remote / Onsite / Hybrid"></div><div><label>Employment type</label><input id="jtype" placeholder="Full-time"></div><div><label>Minimum experience</label><input id="jexp" type="number" value="0"></div><div class="wide"><label>Required skills</label><input id="jskills" placeholder="Python, JavaScript, SQL"></div><div class="wide"><label>Required qualifications</label><input id="jquals" placeholder="B.Sc. Computer Science, HND..."></div><div class="wide"><label>Required certificates</label><input id="jcerts" placeholder="AWS, Cisco, PMP..."></div><div class="wide"><label>Application URL</label><input id="jurl" placeholder="https://..."></div><div><label>Active</label><select id="jactive"><option value="1">Yes</option><option value="0">No</option></select></div></div><button class="btn" style="margin-top:14px" onclick="saveJob()">Add Job</button><div id="jobs" style="margin-top:16px"></div></section><section class="panel" style="margin-top:16px"><h2>Issue Credential</h2><div class="grid"><div><label>Member AVELYX ID</label><input id="cavx" placeholder="AVX-..."></div><div><label>Credential title</label><input id="ctitle" placeholder="B.Sc. Computer Science"></div><div><label>Credential type</label><input id="ctype" placeholder="Education"></div><div><label>Issuer</label><input id="cissuer" placeholder="University / Employer"></div><div><label>Reference</label><input id="cref"></div><div><label>Initial status</label><select id="cstatus"><option value="pending">Pending</option><option value="verified">Verified</option><option value="unverified">Unverified</option></select></div></div><button class="btn" style="margin-top:14px" onclick="createCredential()">Issue Credential</button><div id="credentialMsg"></div><div id="credentialsAdmin" style="margin-top:16px" class="muted">Loading...</div></section>`,`<script>let data;const labels={avx_enabled:'AVX Credits',global_search_enabled:'Global Search',verified_credentials_enabled:'Verified Credentials',verify_mark_enabled:'Verify Credential Mark',cards_enabled:'AVELYX Cards',job_search_enabled:'Job Search'};const esc=(s)=>String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));async function load(){const r=await fetch('/api/admin/platform');if(r.status===403){document.body.innerHTML='<main class="public"><section class="profile-card"><h1>Admin access required</h1><p class="sub">Set ADMIN_EMAIL to your AVELYX account email in Worker variables.</p></section></main>';return}data=await r.json();settings.innerHTML=Object.entries(labels).map(([k,v])=>'<div class="field"><b>'+v+'</b><br><span class="pill">'+(data.settings[k]==='1'?'LIVE':'COMING SOON')+'</span><br><button class="btn ghost" style="margin-top:10px" onclick="toggleSetting(\''+k+'\','+(data.settings[k]==='1'?'false':'true')+')">'+(data.settings[k]==='1'?'Turn Off':'Launch')+'</button></div>').join('');packages.innerHTML=(data.packages||[]).map(p=>'<div class="field"><b>'+esc(p.name)+'</b> · ₦'+Number(p.price_ngn).toLocaleString()+' · '+Number(p.avx_amount).toLocaleString()+' AVX<br><small>'+esc(p.description||'')+' · '+(p.active?'ACTIVE':'DRAFT')+'</small><br><button class="btn ghost" onclick="editPackage('+p.id+')">Edit</button> <button class="btn ghost" onclick="deletePackage('+p.id+')">Delete</button></div>').join('')||'<p class="muted">No packages yet.</p>';members.innerHTML=(data.profiles||[]).slice(0,20).map(p=>'<div class="field"><b>'+esc(p.full_name)+'</b><br>'+esc(p.avx_id)+' · '+esc((p.account_type||'individual').toUpperCase())+' · '+esc((p.card_tier||'basic').toUpperCase())+' · '+Number(p.avx_balance||0)+' AVX · WALLET OPEN</div>').join('');const t=data.treasury;if(t){const max=Number(t.max_supply||0),unlocked=Number(t.unlocked_amount||0),issued=Number(t.issued_amount||0);treasuryBox.innerHTML='<b>Maximum supply:</b> '+max.toLocaleString()+' AVX<br><b>Unlocked:</b> '+unlocked.toLocaleString()+' AVX<br><b>Issued:</b> '+issued.toLocaleString()+' AVX<br><b>Available to issue:</b> '+Math.max(0,unlocked-issued).toLocaleString()+' AVX<br><span class="pill">'+(Number(t.locked)===1?'🔒 LOCKED':'● UNLOCKED')+'</span>'}jobs.innerHTML=(data.jobs||[]).map(j=>'<div class="field"><b>'+esc(j.title)+'</b> · '+esc(j.employer)+'<br><small>'+esc(j.location||'')+' · '+(j.active?'ACTIVE':'OFF')+' · '+esc(j.required_skills||'')+'</small><br><button class="btn ghost" onclick="toggleJob('+j.id+','+(!j.active)+')">'+(j.active?'Deactivate':'Activate')+'</button> <button class="btn ghost" onclick="deleteJob('+j.id+')">Delete</button></div>').join('')||'<p class="muted">No job listings.</p>';const cr=await fetch('/api/admin/credentials');const cd=await cr.json();credentialsAdmin.innerHTML=(cd.credentials||[]).map(c=>'<div class="field"><b>'+esc(c.full_name)+' · '+esc(c.title)+'</b><br><span class="pill">'+esc(c.status.toUpperCase())+'</span> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'verified\')">Verify</button> <button class="btn ghost" onclick="setCredential(\''+c.credential_id+'\',\'revoked\')">Revoke</button> <a class="share-url" href="/c/'+encodeURIComponent(c.credential_id)+'" target="_blank">Public page</a></div>').join('')||'<p class="muted">No credentials.</p>'}async function toggleSetting(key,value){const r=await fetch('/api/admin/platform/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key,value})});if(!r.ok)alert((await r.json()).error);load()}async function savePackage(){const b={id:window.editingPackage||null,name:pname.value,price_ngn:pprice.value,avx_amount:pamount.value,description:pdesc.value,active:pactive.value==='1',sort_order:psort.value};const r=await fetch('/api/admin/packages',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok){alert(d.error);return}window.editingPackage=null;pname.value='';pprice.value='';pamount.value='';pdesc.value='';psort.value='0';pactive.value='1';load()}function editPackage(id){const p=data.packages.find(x=>x.id===id);if(!p)return;window.editingPackage=id;pname.value=p.name;pprice.value=p.price_ngn;pamount.value=p.avx_amount;pdesc.value=p.description||'';pactive.value=p.active?'1':'0';psort.value=p.sort_order||0;document.querySelector('#pname').scrollIntoView({behavior:'smooth'})}async function deletePackage(id){if(!confirm('Delete this package?'))return;await fetch('/api/admin/packages/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}async function unlockTreasury(){const amount=Number(unlockAmount.value||0);if(!amount||amount<=0){treasuryMsg.className='error';treasuryMsg.textContent='Enter a valid unlock amount.';return}if(!confirm('Unlock '+amount.toLocaleString()+' AVX from the locked treasury?'))return;const r=await fetch('/api/admin/treasury/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({amount})});const d=await r.json();treasuryMsg.className=r.ok?'toast':'error';treasuryMsg.textContent=r.ok?'Unlocked '+Number(d.available_to_issue).toLocaleString()+' AVX available for issuance.':d.error;unlockAmount.value='';load()}async function creditWallet(){const r=await fetch('/api/admin/wallet/credit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({avx_id:wavx.value,amount:wamount.value,reference:wref.value,note:wnote.value})});const d=await r.json();walletMsg.className=r.ok?'toast':'error';walletMsg.textContent=r.ok?'Wallet credited. New balance: '+d.new_balance+' AVX':d.error;load()}async function saveJob(){const b={title:jtitle.value,employer:jemployer.value,location:jlocation.value,work_mode:jmode.value,employment_type:jtype.value,min_experience:jexp.value,required_skills:jskills.value,required_qualifications:jquals.value,required_certificates:jcerts.value,apply_url:jurl.value,active:jactive.value==='1'};const r=await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();if(!r.ok){alert(d.error);return}['jtitle','jemployer','jlocation','jmode','jtype','jexp','jskills','jquals','jcerts','jurl'].forEach(id=>document.getElementById(id).value='');load()}async function toggleJob(id,on){const j=data.jobs.find(x=>x.id===id);if(!j)return;const b={id,title:j.title,employer:j.employer,location:j.location,work_mode:j.work_mode,employment_type:j.employment_type,min_experience:j.min_experience,required_skills:j.required_skills,required_qualifications:j.required_qualifications,required_certificates:j.required_certificates,apply_url:j.apply_url,active:on};await fetch('/api/admin/jobs',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});load()}async function deleteJob(id){if(!confirm('Delete this job?'))return;await fetch('/api/admin/jobs/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id})});load()}async function createCredential(){const b={avx_id:cavx.value,title:ctitle.value,credential_type:ctype.value,issuer:cissuer.value,reference:cref.value,status:cstatus.value};const r=await fetch('/api/admin/credentials',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});const d=await r.json();credentialMsg.className=r.ok?'toast':'error';credentialMsg.textContent=r.ok?'Created '+d.credential_id:d.error;if(r.ok){cavx.value=ctitle.value=ctype.value=cissuer.value=cref.value='';load()}}async function setCredential(id,status){const r=await fetch('/api/admin/credentials/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_id:id,status})});if(!r.ok)alert((await r.json()).error);load()}load()</script>`)}

export default { async fetch(request, env) {
  const url = new URL(request.url);
  try {
    if (url.pathname === '/api/register' && request.method === 'POST') return await register(request, env);
    if (url.pathname === '/api/login' && request.method === 'POST') return await login(request, env);
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
    if (url.pathname === '/api/verification/requests' && request.method === 'GET') return await verificationRequests(request, env);
    if (url.pathname === '/api/verification/requests' && request.method === 'POST') return await createVerificationRequest(request, env);
    if (url.pathname === '/api/information-requests/sent' && request.method === 'GET') return await sentInformationRequests(request, env);
    if (url.pathname === '/api/information-requests' && request.method === 'GET') return await informationRequests(request, env);
    if (url.pathname === '/api/information-requests' && request.method === 'POST') return await createInformationRequest(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'GET') return await adminCredentials(request, env);
    if (url.pathname === '/api/admin/credentials' && request.method === 'POST') return await adminCreateCredential(request, env);
    if (url.pathname === '/api/admin/credentials/status' && request.method === 'POST') return await adminUpdateCredential(request, env);
    if (url.pathname === '/api/logout' && request.method === 'POST') return await logout(request, env);
    if (url.pathname === '/api/me') return await me(request, env);
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
    if (url.pathname.startsWith('/v/')) { const p=await env.DB.prepare('SELECT * FROM profiles WHERE avx_id=?').bind(url.pathname.slice(3)).first(); return p ? renderPublic(p,['full_name','title','organization','industry','location','website','bio','account_type','card_tier'],'AVELYX Profile') : new Response('Profile not found',{status:404}); }
    if (appPages[url.pathname] === 'register') return registerPage();
    if (appPages[url.pathname] === 'login') return loginPage();
    if (appPages[url.pathname] === 'verify') return verifyPage();
    if (appPages[url.pathname] === 'dashboard') return dashboardPage();
    if (appPages[url.pathname] === 'profile') return profilePage();
    if (appPages[url.pathname] === 'qr') return qrPage();
    if (appPages[url.pathname] === 'permissions') return permissionsPage();
    if (appPages[url.pathname] === 'notifications') return notificationsPage();
    if (appPages[url.pathname] === 'wallet') return walletPage();
    if (appPages[url.pathname] === 'opportunities') return opportunitiesPage();
    return env.ASSETS.fetch(request);
  } catch (e) { return json({ error: 'Server error. Please try again.', detail: e?.message || String(e) }, 500); }
}};
