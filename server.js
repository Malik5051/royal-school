'use strict';
/*
  Royal International Schools - website + admission form server.
  No npm packages needed. Run:  node server.js
*/
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'applications.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

const SECTIONS = ['Preschool', 'Primary', 'Secondary'];
const RELATIONSHIPS = ['Mother', 'Father', 'Guardian', 'Other'];
const GENDERS = ['', 'Female', 'Male'];
const STATUSES = ['New', 'Under review', 'Contacted', 'Accepted', 'Waitlisted', 'Declined'];

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- admin password ---------- */
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function saveAdmin(password) {
  fs.writeFileSync(ADMIN_FILE, JSON.stringify(hashPassword(password)), { mode: 0o600 });
}
function checkPassword(password) {
  if (process.env.ADMIN_PASSWORD) return safeEqual(password, process.env.ADMIN_PASSWORD);
  try {
    const a = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
    const h = hashPassword(password, a.salt).hash;
    return safeEqual(h, a.hash);
  } catch (e) { return false; }
}
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

// node server.js --set-password "new password"
const argi = process.argv.indexOf('--set-password');
if (argi !== -1) {
  const pw = process.argv[argi + 1];
  if (!pw || pw.length < 8) { console.error('Password must be at least 8 characters.'); process.exit(1); }
  saveAdmin(pw);
  console.log('Admin password updated.');
  process.exit(0);
}
if (!process.env.ADMIN_PASSWORD && !fs.existsSync(ADMIN_FILE)) {
  const pw = crypto.randomBytes(6).toString('base64url');
  saveAdmin(pw);
  console.log('\n==============================================');
  console.log(' First run: admin password created');
  console.log('   Password: ' + pw);
  console.log(' Write it down. To change it later run:');
  console.log('   node server.js --set-password "your new password"');
  console.log('==============================================\n');
}

/* ---------- storage (JSON file, written atomically) ---------- */
let db = { nextNumber: 1, applications: [] };
try {
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { /* first run */ }
function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

/* ---------- helpers ---------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.ico': 'image/x-icon', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8'
};
function baseHeaders(extra) {
  return Object.assign({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin'
  }, extra);
}
function sendJson(res, status, obj) {
  res.writeHead(status, baseHeaders({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }));
  res.end(JSON.stringify(obj));
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject(Object.assign(new Error('bad json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function clientIp(req) { return (req.socket.remoteAddress || '').replace('::ffff:', ''); }
function str(v, max) { return (typeof v === 'string' ? v : '').trim().slice(0, max); }

/* ---------- rate limits ---------- */
const loginFails = new Map();   // ip -> {count, until}
const submissions = new Map();  // ip -> [timestamps]
function loginBlocked(ip) {
  const f = loginFails.get(ip);
  return f && f.until > Date.now();
}
function loginFailed(ip) {
  const f = loginFails.get(ip) || { count: 0, until: 0 };
  f.count++;
  if (f.count >= 5) { f.until = Date.now() + 5 * 60 * 1000; f.count = 0; }
  loginFails.set(ip, f);
}
function submissionAllowed(ip) {
  const now = Date.now();
  const list = (submissions.get(ip) || []).filter(t => now - t < 3600 * 1000);
  if (list.length >= 8) { submissions.set(ip, list); return false; }
  list.push(now); submissions.set(ip, list); return true;
}

/* ---------- sessions ---------- */
const sessions = new Map(); // token -> expiry
const SESSION_MS = 8 * 3600 * 1000;
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : '';
}
function isAdmin(req) {
  const t = getCookie(req, 'ris_admin');
  const exp = t && sessions.get(t);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(t); return false; }
  return true;
}
function cookieFlags(req) {
  return 'HttpOnly; SameSite=Strict; Path=/' + (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '');
}

/* ---------- validation ---------- */
function validate(b) {
  const errors = {};
  const d = {
    student_first_name: str(b.student_first_name, 100),
    student_last_name: str(b.student_last_name, 100),
    student_dob: str(b.student_dob, 10),
    student_gender: str(b.student_gender, 20),
    section: str(b.section, 20),
    class_applying: str(b.class_applying, 100),
    previous_school: str(b.previous_school, 150),
    parent_name: str(b.parent_name, 120),
    relationship: str(b.relationship, 20),
    phone: str(b.phone, 30),
    email: str(b.email, 150),
    address_area: str(b.address_area, 150),
    tour: b.tour === 'Yes' || b.tour === true ? 'Yes' : '',
    message: str(b.message, 2000)
  };
  if (!d.student_first_name) errors.student_first_name = 'Please fill in this field.';
  if (!d.student_last_name) errors.student_last_name = 'Please fill in this field.';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d.student_dob) || isNaN(Date.parse(d.student_dob))) errors.student_dob = 'Please enter a valid date of birth.';
  else if (d.student_dob > new Date().toISOString().slice(0, 10)) errors.student_dob = 'Date of birth cannot be in the future.';
  else if (d.student_dob < '1990-01-01') errors.student_dob = 'Please check the date of birth.';
  if (!GENDERS.includes(d.student_gender)) d.student_gender = '';
  if (!SECTIONS.includes(d.section)) errors.section = 'Please choose an option.';
  if (!d.parent_name) errors.parent_name = 'Please fill in this field.';
  if (!RELATIONSHIPS.includes(d.relationship)) errors.relationship = 'Please choose an option.';
  if (!/^\+?[\d\s()-]{7,20}$/.test(d.phone)) errors.phone = 'Please enter a valid phone number.';
  if (d.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)) errors.email = 'Please enter a valid email address.';
  if (!(b.consent === 'Yes' || b.consent === true)) errors.consent = 'Please tick this box to continue.';
  return { errors, data: d };
}

/* ---------- API ---------- */
async function handleApi(req, res, pathname) {
  const method = req.method;

  // Public: submit an application
  if (pathname === '/api/applications' && method === 'POST') {
    const body = await readBody(req, 64 * 1024);
    if (str(body._gotcha, 50)) return sendJson(res, 200, { ok: true }); // bot: pretend success, store nothing
    if (!submissionAllowed(clientIp(req))) return sendJson(res, 429, { ok: false, error: 'Too many applications from this connection. Please try again later or call us.' });
    const { errors, data } = validate(body);
    if (Object.keys(errors).length) return sendJson(res, 400, { ok: false, errors });
    const now = new Date().toISOString();
    const year = new Date().getFullYear();
    const app = Object.assign({
      id: crypto.randomUUID(),
      reference: 'RIS-' + year + '-' + String(db.nextNumber++).padStart(4, '0'),
      createdAt: now, updatedAt: now, status: 'New', notes: ''
    }, data);
    db.applications.push(app);
    saveDb();
    return sendJson(res, 201, { ok: true, reference: app.reference });
  }

  // Admin: login / logout / session check
  if (pathname === '/api/admin/login' && method === 'POST') {
    const ip = clientIp(req);
    if (loginBlocked(ip)) return sendJson(res, 429, { ok: false, error: 'Too many attempts. Please wait 5 minutes.' });
    const body = await readBody(req, 4 * 1024);
    if (!checkPassword(str(body.password, 200))) { loginFailed(ip); return sendJson(res, 401, { ok: false, error: 'Wrong password.' }); }
    loginFails.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_MS);
    res.setHeader('Set-Cookie', 'ris_admin=' + token + '; Max-Age=' + (SESSION_MS / 1000) + '; ' + cookieFlags(req));
    return sendJson(res, 200, { ok: true });
  }
  if (pathname === '/api/admin/logout' && method === 'POST') {
    sessions.delete(getCookie(req, 'ris_admin'));
    res.setHeader('Set-Cookie', 'ris_admin=; Max-Age=0; ' + cookieFlags(req));
    return sendJson(res, 200, { ok: true });
  }
  if (pathname === '/api/admin/me' && method === 'GET') {
    return isAdmin(req) ? sendJson(res, 200, { ok: true }) : sendJson(res, 401, { ok: false });
  }

  // Everything below needs an admin session
  if (!pathname.startsWith('/api/admin/')) return sendJson(res, 404, { ok: false, error: 'Not found' });
  if (!isAdmin(req)) return sendJson(res, 401, { ok: false, error: 'Please sign in.' });

  if (pathname === '/api/admin/applications' && method === 'GET') {
    const list = db.applications.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return sendJson(res, 200, { ok: true, statuses: STATUSES, applications: list });
  }

  if (pathname === '/api/admin/export.csv' && method === 'GET') {
    const cols = [
      ['Reference', 'reference'], ['Submitted', 'createdAt'], ['Status', 'status'],
      ['Student first name', 'student_first_name'], ['Student last name', 'student_last_name'],
      ['Date of birth', 'student_dob'], ['Gender', 'student_gender'], ['Section', 'section'],
      ['Class or level', 'class_applying'], ['Previous school', 'previous_school'],
      ['Parent or guardian', 'parent_name'], ['Relationship', 'relationship'], ['Phone', 'phone'],
      ['Email', 'email'], ['Home area', 'address_area'], ['Tour requested', 'tour'],
      ['Message', 'message'], ['Office notes', 'notes']
    ];
    const cell = v => {
      let s = String(v == null ? '' : v);
      // stop spreadsheet formula injection, but leave phone numbers like +211 927 330 101 alone
      if (/^[=+\-@\t\r]/.test(s) && !/^\+?[\d\s()-]{7,}$/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const rows = [cols.map(c => cell(c[0])).join(',')];
    db.applications.slice().sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .forEach(a => rows.push(cols.map(c => cell(a[c[1]])).join(',')));
    res.writeHead(200, baseHeaders({
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="admission-applications-' + new Date().toISOString().slice(0, 10) + '.csv"',
      'Cache-Control': 'no-store'
    }));
    return res.end('\uFEFF' + rows.join('\r\n'));
  }

  const m = pathname.match(/^\/api\/admin\/applications\/([\w-]{1,64})$/);
  if (m) {
    const idx = db.applications.findIndex(a => a.id === m[1]);
    if (idx === -1) return sendJson(res, 404, { ok: false, error: 'Application not found.' });
    if (method === 'PATCH') {
      const body = await readBody(req, 16 * 1024);
      const a = db.applications[idx];
      if (body.status !== undefined) {
        if (!STATUSES.includes(body.status)) return sendJson(res, 400, { ok: false, error: 'Invalid status.' });
        a.status = body.status;
      }
      if (body.notes !== undefined) a.notes = str(body.notes, 4000);
      a.updatedAt = new Date().toISOString();
      saveDb();
      return sendJson(res, 200, { ok: true, application: a });
    }
    if (method === 'DELETE') {
      db.applications.splice(idx, 1);
      saveDb();
      return sendJson(res, 200, { ok: true });
    }
  }
  return sendJson(res, 404, { ok: false, error: 'Not found' });
}

/* ---------- static files ---------- */
const PAGES = { '/': 'index.html', '/index': 'index.html', '/admission': 'admission.html', '/admin': 'admin.html' };
function serveStatic(req, res, pathname) {
  let rel = PAGES[pathname] || decodeURIComponent(pathname).replace(/^\/+/, '');
  const file = path.normalize(path.join(PUBLIC, rel));
  if (file !== PUBLIC && !file.startsWith(PUBLIC + path.sep)) { res.writeHead(403, baseHeaders()); return res.end('Forbidden'); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, baseHeaders({ 'Content-Type': 'text/html; charset=utf-8' }));
      return res.end('<!doctype html><meta charset="utf-8"><title>Not found</title><p style="font-family:sans-serif;padding:40px">Page not found. <a href="/">Go to the home page</a>.</p>');
    }
    const isAdminPage = path.basename(file) === 'admin.html';
    res.writeHead(200, baseHeaders({
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': isAdminPage ? 'no-store' : 'public, max-age=300'
    }));
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  try {
    const pathname = new URL(req.url, 'http://x').pathname;
    if (pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const ct = (req.headers['content-type'] || '');
        if (req.method !== 'DELETE' && !ct.includes('application/json')) return sendJson(res, 415, { ok: false, error: 'JSON required.' });
      }
      return await handleApi(req, res, pathname);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, baseHeaders()); return res.end('Method not allowed'); }
    return serveStatic(req, res, pathname);
  } catch (e) {
    if (!res.headersSent) sendJson(res, e.status || 500, { ok: false, error: e.status ? e.message : 'Server error.' });
    if (!e.status) console.error(e);
  }
});

server.listen(PORT, HOST, () => {
  console.log('Royal International Schools server is running');
  console.log('  Website : http://localhost:' + PORT + '/');
  console.log('  Admin   : http://localhost:' + PORT + '/admin');
  console.log('Press Ctrl+C to stop.');
});
