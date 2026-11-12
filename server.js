const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data.json');
const INDEX = path.join(__dirname, 'public', 'index.html');

// Ordre croissant : l'index sert à comparer les grades
const GRADES = ['US Marshal 3', 'US Marshal 2', 'US Marshal 1', 'Chef adjoint', 'Commandant'];
const SOG_MIN_GRADE = 2; // US Marshal 1

const SOG_QUESTIONS = [
  'Pourquoi souhaitez-vous rejoindre la SOG ?',
  'Décrivez votre expérience en intervention tactique.',
  'Comment réagissez-vous face à une prise d’otage ?',
  'Quelles règles d’usage de la force devez-vous respecter avant une intervention ?',
  'Comment assurez-vous la sécurité de votre équipe lors d’une progression ?',
  'Quelles qualités sont indispensables selon vous pour un membre de la SOG ?',
];

const db = fs.existsSync(DATA)
  ? JSON.parse(fs.readFileSync(DATA, 'utf8'))
  : { agents: [], equipment: [], recruitment: [], nextId: 1 };
const save = () => fs.writeFileSync(DATA, JSON.stringify(db, null, 2));
const sessions = new Map(); // token -> id agent

function hash(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function verify(agent, pw) {
  const h = crypto.scryptSync(pw, agent.salt, 64);
  return crypto.timingSafeEqual(h, Buffer.from(agent.hash, 'hex'));
}
function publicAgent(a) {
  const { salt, hash: _h, ...rest } = a;
  return rest;
}

// Compte admin initial : mot de passe défini via ADMIN_PASSWORD (sinon généré et affiché)
if (!db.agents.some((a) => a.role === 'admin')) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64');
  const email = process.env.ADMIN_EMAIL || 'admin@usmarshal.fw';
  db.agents.push({
    id: db.nextId++, email, name: 'Administrateur', grade: 'Commandant',
    role: 'admin', canRecruit: true, ...hash(pw),
  });
  save();
  console.log(`Compte admin créé : ${email} / ${pw}`);
}

function json(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
function body(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => (d += c));
    req.on('end', () => {
      try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); }
    });
  });
}
function currentAgent(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const id = sessions.get(token);
  return id ? db.agents.find((a) => a.id === id) : null;
}

async function handle(req, res) {
  const p = new URL(req.url, 'http://x').pathname;

  if (!p.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return fs.createReadStream(INDEX).pipe(res);
  }

  const b = req.method === 'GET' ? {} : await body(req);
  const id = Number(p.split('/')[3]);

  if (p === '/api/login' && req.method === 'POST') {
    const a = db.agents.find((x) => x.email === b.email);
    if (!a || !verify(a, String(b.password || ''))) return json(res, 401, { error: 'Identifiants invalides' });
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, a.id);
    return json(res, 200, { token, agent: publicAgent(a) });
  }

  const me = currentAgent(req);
  if (!me) return json(res, 401, { error: 'Non connecté' });
  const admin = me.role === 'admin';
  const deny = () => json(res, 403, { error: 'Accès refusé' });

  if (p === '/api/me') return json(res, 200, publicAgent(me));
  if (p === '/api/logout') {
    sessions.delete((req.headers.authorization || '').replace('Bearer ', ''));
    return json(res, 200, { ok: true });
  }
  if (p === '/api/grades') return json(res, 200, GRADES);

  // Agents
  if (p === '/api/agents' && req.method === 'GET') return json(res, 200, db.agents.map(publicAgent));
  if (p === '/api/agents' && req.method === 'POST') {
    if (!admin) return deny();
    if (db.agents.some((a) => a.email === b.email)) return json(res, 400, { error: 'E-mail déjà utilisé' });
    const a = {
      id: db.nextId++, email: b.email, name: b.name, grade: b.grade, role: 'agent',
      canRecruit: !!b.canRecruit, ...hash(String(b.password || '')),
    };
    db.agents.push(a);
    save();
    return json(res, 201, publicAgent(a));
  }
  if (p.startsWith('/api/agents/') && (req.method === 'PUT' || req.method === 'DELETE')) {
    if (!admin) return deny();
    const a = db.agents.find((x) => x.id === id);
    if (!a) return json(res, 404, { error: 'Agent introuvable' });
    if (req.method === 'DELETE') {
      if (a.role === 'admin') return json(res, 400, { error: 'Impossible de supprimer un admin' });
      db.agents = db.agents.filter((x) => x !== a);
      save();
      return json(res, 200, { ok: true });
    }
    for (const k of ['email', 'name', 'grade', 'canRecruit']) if (k in b) a[k] = b[k];
    if (b.password) Object.assign(a, hash(String(b.password)));
    save();
    return json(res, 200, publicAgent(a));
  }

  // Équipements
  if (p === '/api/equipment' && req.method === 'GET') return json(res, 200, db.equipment);
  if (p === '/api/equipment' && req.method === 'POST') {
    if (!admin) return deny();
    const e = {
      id: db.nextId++, serial: b.serial, type: b.type,
      quantity: Number(b.quantity) || 1, assignedTo: b.assignedTo || '',
    };
    db.equipment.push(e);
    save();
    return json(res, 201, e);
  }
  if (p.startsWith('/api/equipment/') && req.method === 'DELETE') {
    if (!admin) return deny();
    db.equipment = db.equipment.filter((e) => e.id !== id);
    save();
    return json(res, 200, { ok: true });
  }

  // Recrutement SOG
  const canRecruit = admin || me.canRecruit;
  if (p === '/api/recruitment/sessions' && req.method === 'GET') {
    if (!canRecruit) return deny();
    return json(res, 200, db.recruitment);
  }
  if (p === '/api/recruitment/sessions' && req.method === 'POST') {
    if (!canRecruit) return deny();
    const s = {
      id: db.nextId++, code: crypto.randomBytes(3).toString('hex').toUpperCase(),
      openedBy: me.name, createdAt: new Date().toISOString(), active: true,
      questions: SOG_QUESTIONS, submissions: [],
    };
    db.recruitment.push(s);
    save();
    return json(res, 201, { id: s.id, code: s.code });
  }
  if (p === '/api/recruitment/join' && req.method === 'POST') {
    if (!admin && GRADES.indexOf(me.grade) < SOG_MIN_GRADE) return deny();
    const s = db.recruitment.find((x) => x.active && x.code === String(b.code || '').toUpperCase());
    if (!s) return json(res, 404, { error: 'Code invalide ou session fermée' });
    return json(res, 200, { sessionId: s.id, questions: s.questions });
  }
  if (p === '/api/recruitment/submit' && req.method === 'POST') {
    if (!admin && GRADES.indexOf(me.grade) < SOG_MIN_GRADE) return deny();
    const s = db.recruitment.find((x) => x.active && x.id === Number(b.sessionId));
    if (!s) return json(res, 404, { error: 'Session fermée' });
    s.submissions.push({ agent: me.name, answers: b.answers || [], at: new Date().toISOString() });
    save();
    return json(res, 201, { ok: true });
  }

  return json(res, 404, { error: 'Route inconnue' });
}

const server = http.createServer(async (req, res) => {
  try {
    await handle(req, res);
  } catch (e) {
    json(res, 500, { error: 'Erreur interne' });
  }
});
server.listen(PORT, () => console.log(`US Marshal en ligne : http://localhost:${PORT}`));
