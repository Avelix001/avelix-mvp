const SESSION_COOKIE = '__Host-avelix_session';
const SESSION_DAYS = 7;
const QR_MINUTES = 30;

const esc = (v = '') => String(v).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=UTF-8', 'cache-control': 'no-store' }});
const now = () => Math.floor(Date.now() / 1000);
const makeId = () => `AVX-${crypto.randomUUID().replaceAll('-', '').slice(0, 10).toUpperCase()}`;
const randomToken = () => crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');

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
  const fullName = String(body.full_name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!fullName || !email || password.length < 8) return json({ error: 'Name, email and a password of at least 8 characters are required.' }, 400);
  const exists = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
  if (exists) return json({ error: 'An account with this email already exists. Please log in.' }, 409);
  const avxId = makeId();
  const hash = await passwordHash(password);
  const statements = [
    env.DB.prepare(`INSERT INTO profiles (avx_id, full_name, title, organization, industry, location, email, phone, website, bio, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`).bind(avxId, fullName, body.title || '', body.organization || '', body.industry || '', body.location || '', email, body.phone || '', body.website || '', body.bio || ''),
  ];
  await env.DB.batch(statements);
  const profile = await env.DB.prepare('SELECT id FROM profiles WHERE avx_id=?').bind(avxId).first();
  try {
    await env.DB.prepare('INSERT INTO users (profile_id, email, password_hash) VALUES (?, ?, ?)').bind(profile.id, email, hash).run();
  } catch (e) {
    await env.DB.prepare('DELETE FROM profiles WHERE id=?').bind(profile.id).run();
    throw e;
  }
  const user = await env.DB.prepare('SELECT id FROM users WHERE profile_id=?').bind(profile.id).first();
  const token = await createSession(user.id, env);
  const response = json({ ok: true, avx_id: avxId, message: 'Your AVELIX profile has been created.' }, 201);
  return withSession(response, token);
}

async function login(request, env) {
  const body = await request.json();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE email=?').bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) return json({ error: 'Invalid email or password.' }, 401);
  const token = await createSession(user.id, env);
  return withSession(json({ ok: true }), token);
}

async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
  return withSession(json({ ok: true }), '', 0);
}

async function me(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ authenticated: false }, 401);
  return json({ authenticated: true, profile: user });
}

async function updateProfile(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Please log in.' }, 401);
  const body = await request.json();
  await env.DB.prepare(`UPDATE profiles SET full_name=?, title=?, organization=?, industry=?, location=?, email=?, phone=?, website=?, bio=? WHERE id=?`)
    .bind(String(body.full_name || '').trim(), body.title || '', body.organization || '', body.industry || '', body.location || '', String(body.email || '').trim().toLowerCase(), body.phone || '', body.website || '', body.bio || '', user.id)
    .run();
  return json({ ok: true });
}

async function revokeShare(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  await env.DB.prepare('UPDATE share_tokens SET revoked_at=? WHERE profile_id=? AND used_at IS NULL AND revoked_at IS NULL').bind(now(), user.id).run();
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
    env.DB.prepare('INSERT INTO share_tokens (profile_id, token_hash, fields_json, expires_at, max_uses) VALUES (?, ?, ?, ?, 1)').bind(user.id, await sha256(token), JSON.stringify(fields), expiresAt),
  ]);
  const url = new URL(request.url); url.pathname = `/s/${token}`; url.search = '';
  return json({ ok: true, url: url.toString(), expires_at: expiresAt, max_uses: 1, fields });
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
  return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${styles()}</head><body><main class="public"><div class="brand">AVELIX<span>◆</span></div><section class="profile-card"><div class="eyebrow">${secure ? 'SECURE ONE-SCAN SHARE' : 'AVELIX PROFESSIONAL PROFILE'}</div><h1>${esc(p.full_name)}</h1><p class="sub">${esc(p.title || '')}${p.organization ? ` · ${esc(p.organization)}` : ''}</p><div class="status">● ${esc(p.status || 'active')}</div><div class="fields">${rows}</div><div class="idbox"><small>AVELIX ID</small><b>${esc(p.avx_id)}</b></div>${secure ? '<p class="notice">This secure QR link was designed for one scan and is now consumed.</p>' : ''}</section><p class="foot">AVELIX — Prove Your Potential.</p></main></body></html>`, { headers: { 'content-type': 'text/html; charset=UTF-8' }});
}
function renderShareExpired() { return new Response(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>QR Expired • AVELIX</title>${styles()}</head><body><main class="public"><div class="brand">AVELIX<span>◆</span></div><section class="profile-card center"><div class="eyebrow">SECURE QR STATUS</div><h1>QR Expired</h1><p class="sub">This secure AVELIX QR code is no longer valid. Generate a new QR from the member dashboard.</p><div class="status bad">● EXPIRED</div></section></main></body></html>`, { status: 410, headers: { 'content-type': 'text/html; charset=UTF-8' }}); }
function styles() { return `<style>:root{--bg:#050817;--panel:#0c1430;--line:#202b50;--text:#f7f8ff;--muted:#9ca9ca;--purple:#8b4dff;--blue:#159cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#17153c 0,#050817 42%);color:var(--text);font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}.public{max-width:760px;margin:auto;padding:48px 20px}.brand{font-weight:900;font-size:26px;letter-spacing:.18em;margin-bottom:34px}.brand span{color:var(--blue);font-size:12px;margin-left:8px}.profile-card{background:linear-gradient(145deg,#111a3a,#080d21);border:1px solid var(--line);border-radius:28px;padding:34px;box-shadow:0 24px 70px #0008}.center{text-align:center}.eyebrow{font-size:11px;letter-spacing:.18em;color:#8ea3d8;font-weight:800}h1{font-size:42px;line-height:1.05;margin:14px 0 8px}.sub{color:var(--muted);font-size:17px}.status{display:inline-block;margin:18px 0;padding:8px 12px;border:1px solid #275f49;border-radius:999px;color:#67e0a1;font-size:12px;text-transform:uppercase;letter-spacing:.08em}.status.bad{border-color:#693345;color:#ff879e}.fields{display:grid;gap:10px;margin-top:12px}.field{padding:15px;border:1px solid #1d2748;border-radius:14px;background:#070c1d}.field span{display:block;color:#7785aa;font-size:11px;text-transform:uppercase;letter-spacing:.12em;margin-bottom:5px}.field strong{font-size:15px;word-break:break-word}.field a{color:#65baff}.idbox{margin-top:18px;padding:18px;border-radius:16px;background:#0a1229;border:1px solid #27365e}.idbox small{display:block;color:#7484a8;font-size:10px;letter-spacing:.14em}.idbox b{display:block;margin-top:5px;letter-spacing:.1em}.notice{color:#ffbd68;font-size:13px}.foot{text-align:center;color:#657294;margin-top:24px;font-size:12px}</style>`; }

const appPages = {
  '/register.html': 'register', '/login.html':'login', '/dashboard.html':'dashboard'
};
function shell(title, content, script='') { return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} • AVELIX</title>${styles()}<style>.app{max-width:1050px;margin:auto;padding:24px 18px 60px}.nav{display:flex;justify-content:space-between;align-items:center;padding:10px 0 34px}.nav a{color:#b8c3e1;text-decoration:none;margin-left:18px}.btn{border:0;border-radius:12px;padding:13px 18px;font-weight:800;cursor:pointer;color:white;background:linear-gradient(135deg,var(--purple),var(--blue));box-shadow:0 10px 30px #315bff22}.btn.ghost{background:#111a36;border:1px solid var(--line);box-shadow:none}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.panel{background:#0b122a;border:1px solid var(--line);border-radius:22px;padding:24px}.panel h2{margin-top:0}.muted{color:var(--muted)}label{display:block;font-size:12px;color:#9aa8c9;margin:13px 0 7px}input,textarea,select{width:100%;padding:13px 14px;border-radius:12px;border:1px solid #263354;background:#070d20;color:white;outline:none}textarea{min-height:100px;resize:vertical}.wide{grid-column:1/-1}.toast{margin-top:12px;color:#7ee8b1}.error{color:#ff91a5;margin-top:12px}.hero{padding:34px 0 22px}.hero h1{font-size:46px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.soon{opacity:.62;position:relative;overflow:hidden}.soon:after{content:'COMING SOON';position:absolute;top:15px;right:-31px;transform:rotate(35deg);background:#1d2850;padding:6px 38px;font-size:9px;letter-spacing:.12em}.qrbox{text-align:center}.qrbox canvas,.qrbox img{max-width:260px;margin:16px auto;display:block;background:white;padding:10px;border-radius:14px}.pill{display:inline-block;padding:7px 10px;border-radius:999px;background:#101b3b;color:#9eb1de;font-size:11px}.share-url{word-break:break-all;color:#73bdff;font-size:12px}.actions{display:flex;gap:10px;flex-wrap:wrap}@media(max-width:760px){.grid,.cards{grid-template-columns:1fr}.hero h1{font-size:35px}h1{font-size:34px}}</style></head><body><div class="app"><nav class="nav"><a href="/" style="font-weight:900;font-size:22px;letter-spacing:.15em;color:white">AVELIX</a><div><a href="/dashboard.html">Dashboard</a><a href="/login.html">Login</a></div></nav>${content}</div>${script}</body></html>`, {headers:{'content-type':'text/html; charset=UTF-8'}}); }
function registerPage(){return shell('Create Profile',`<section class="hero"><div class="eyebrow">JOIN AVELIX</div><h1>Create your digital professional identity.</h1><p class="muted">Register your AVELIX profile, receive your unique AVELIX ID, and manage your profile from your private dashboard.</p></section><section class="panel"><div class="grid"><div class="wide"><label>Full name *</label><input id="full_name" placeholder="Your full name"></div><div><label>Email *</label><input id="email" type="email" placeholder="you@example.com"></div><div><label>Password *</label><input id="password" type="password" placeholder="At least 8 characters"></div><div><label>Professional title</label><input id="title" placeholder="e.g. Software Developer"></div><div><label>Organization</label><input id="organization" placeholder="Company / school / business"></div><div><label>Industry</label><input id="industry" placeholder="e.g. Technology"></div><div><label>Location</label><input id="location" placeholder="City, Country"></div><div><label>Phone</label><input id="phone" placeholder="Optional"></div><div><label>Website</label><input id="website" placeholder="https://..."></div><div class="wide"><label>Short bio</label><textarea id="bio" placeholder="Tell people what you do..."></textarea></div><div class="wide actions"><button class="btn" onclick="register()">Create My AVELIX ID</button><span id="msg"></span></div></div></section>`,`<script>async function register(){const ids=['full_name','email','password','title','organization','industry','location','phone','website','bio'];const body=Object.fromEntries(ids.map(id=>[id,document.getElementById(id).value]));const r=await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}msg.className='toast';msg.innerHTML='Profile created: <b>'+d.avx_id+'</b> — taking you to your dashboard...';setTimeout(()=>location.href='/dashboard.html',700)}</script>`);}
function loginPage(){return shell('Login',`<section class="hero"><div class="eyebrow">AVELIX MEMBER ACCESS</div><h1>Welcome back.</h1><p class="muted">Access your profile, secure QR tools and member features.</p></section><section class="panel" style="max-width:560px"><label>Email</label><input id="email" type="email"><label>Password</label><input id="password" type="password"><div class="actions" style="margin-top:18px"><button class="btn" onclick="login()">Log In</button><a class="btn ghost" href="/register.html">Create Account</a></div><div id="msg"></div></section>`,`<script>async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){msg.className='error';msg.textContent=d.error;return}location.href='/dashboard.html'}</script>`);}
function dashboardPage(){return shell('Dashboard',`<section class="hero"><div class="eyebrow">MY AVELIX DASHBOARD</div><h1 id="hello">Your AVELIX</h1><p class="muted">Manage your professional identity and securely share selected profile information.</p><div class="actions"><button class="btn" onclick="generateQR()">Generate Secure QR</button><a class="btn ghost" href="#profile">Edit Profile</a><button class="btn ghost" onclick="logout()">Log Out</button></div></section><section class="grid"><div class="panel" id="profile"><h2>Profile</h2><div id="profileFields" class="muted">Loading...</div></div><div class="panel qrbox"><h2>Secure QR</h2><span class="pill">1 scan · 30 minutes</span><div id="qr"></div><p id="qrmsg" class="muted">Generate a temporary QR when you need to share your profile.</p></div><div class="panel wide"><h2>Share My AVELIX</h2><p class="muted">Your permanent AVELIX profile can be viewed from your profile ID. Secure QR sharing is temporary and limited to one scan.</p><a id="profileLink" class="share-url"></a></div></section><section class="hero"><div class="eyebrow">THE AVELIX ECOSYSTEM</div><h2>More capabilities are coming.</h2></section><section class="cards"><div class="panel soon"><h3>Verified Credentials</h3><p class="muted">Education, employment, certifications and professional credentials can be submitted for real verification.</p></div><div class="panel soon"><h3>Basic AVELIX Card</h3><p class="muted">A future physical and digital identity card connected to your AVELIX profile.</p></div><div class="panel soon"><h3>Platinum AVELIX Card</h3><p class="muted">Premium verified identity and credential services, coming after the verification system is ready.</p></div></section>`,`<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>let me;async function load(){const r=await fetch('/api/me');if(!r.ok){location.href='/login.html';return}me=(await r.json()).profile;hello.textContent='Welcome, '+me.full_name;profileFields.innerHTML='<p><span class="pill">'+me.avx_id+'</span></p><p><b>'+me.full_name+'</b><br>'+[me.title,me.organization,me.location].filter(Boolean).join(' · ')+'</p><label>Update profile</label><input id="full_name" value="'+(me.full_name||'').replaceAll('"','&quot;')+'"><input id="title" style="margin-top:8px" value="'+(me.title||'').replaceAll('"','&quot;')+'"><textarea id="bio" style="margin-top:8px">'+(me.bio||'')+'</textarea><button class="btn" style="margin-top:10px" onclick="save()">Save Changes</button>';profileLink.href='/v/'+me.avx_id;profileLink.textContent=location.origin+'/v/'+me.avx_id}async function save(){await fetch('/api/profile',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({full_name:full_name.value,title:title.value,bio:bio.value,email:me.email,organization:me.organization,industry:me.industry,location:me.location,phone:me.phone,website:me.website})});load()}async function generateQR(){const r=await fetch('/api/share',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({fields:['full_name','title','organization','industry','location','website','bio']})});const d=await r.json();if(!r.ok){qrmsg.className='error';qrmsg.textContent=d.error;return}qr.innerHTML='';new QRCode(qr,{text:d.url,width:230,height:230});qrmsg.innerHTML='<b>Valid for 1 scan.</b><br>'+new Date(d.expires_at*1000).toLocaleString()+'<br><span class="share-url">'+d.url+'</span><br><br><button class="btn ghost" onclick="generateQR()">Generate New QR</button>'}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/'}load()</script>`);}

export default { async fetch(request, env) {
  const url = new URL(request.url);
  try {
    if (url.pathname === '/api/register' && request.method === 'POST') return await register(request, env);
    if (url.pathname === '/api/login' && request.method === 'POST') return await login(request, env);
    if (url.pathname === '/api/logout' && request.method === 'POST') return await logout(request, env);
    if (url.pathname === '/api/me') return await me(request, env);
    if (url.pathname === '/api/profile' && request.method === 'PUT') return await updateProfile(request, env);
    if (url.pathname === '/api/share' && request.method === 'POST') return await generateShare(request, env);
    if (url.pathname.startsWith('/s/')) return await scanShare(url.pathname.slice(3), env);
    if (url.pathname.startsWith('/v/')) { const p=await env.DB.prepare('SELECT * FROM profiles WHERE avx_id=?').bind(url.pathname.slice(3)).first(); return p ? renderPublic(p,['full_name','title','organization','industry','location','website','bio'],'AVELIX Profile') : new Response('Profile not found',{status:404}); }
    if (appPages[url.pathname] === 'register') return registerPage();
    if (appPages[url.pathname] === 'login') return loginPage();
    if (appPages[url.pathname] === 'dashboard') return dashboardPage();
    return env.ASSETS.fetch(request);
  } catch (e) { return json({ error: 'Server error. Please try again.', detail: e?.message || String(e) }, 500); }
}};
