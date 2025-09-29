const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Paths
const DATA_DIR = path.join(__dirname, 'data');
const ANNOUNCEMENTS_PATH = path.join(DATA_DIR, 'announcements.json');
const ARTICLES_PATH = path.join(DATA_DIR, 'articles.json');
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const RECORDS_PATH = path.join(DATA_DIR, 'records.json');
const AUDIT_PATH = path.join(DATA_DIR, 'audit.json');
const ADMINS_PATH = path.join(DATA_DIR, 'admins.json');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const SITE_PATH = path.join(DATA_DIR, 'site.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Helpers to read/write JSON
function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const content = fs.readFileSync(filePath, 'utf-8');
    return content ? JSON.parse(content) : fallback;
  } catch (err) {
    console.error('Failed to read JSON', filePath, err);
    return fallback;
  }
}

function writeJson(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write JSON', filePath, err);
  }
}

function appendAuditLog(entry) {
  try {
    const logs = readJson(AUDIT_PATH, []);
    logs.unshift({ id: String(Date.now()), ...entry });
    writeJson(AUDIT_PATH, logs.slice(0, 5000));
  } catch (e) {
    console.error('Failed to append audit log', e);
  }
}

// Generate next studentId sequentially, preserving width
function generateNextStudentId() {
  const users = readJson(USERS_PATH, []);
  if (!users.length) return '20230001';
  const maxLen = Math.max(...users.map(u => String(u.studentId).length));
  const maxNum = users.reduce((m, u) => Math.max(m, Number(u.studentId) || 0), 0);
  const nextNum = maxNum + 1;
  return String(nextNum).padStart(maxLen, '0');
}

// Normalize a studentId to the canonical one in users.json (handles missing leading zeros)
function normalizeStudentId(inputId) {
  const raw = String((inputId || '').toString().trim());
  const users = readJson(USERS_PATH, []);
  // exact match
  const exact = users.find((u) => u.studentId === raw);
  if (exact) return exact.studentId;
  // numeric equality match (treat 2023001 equal to 20230001)
  const asNum = Number(raw);
  if (!Number.isNaN(asNum)) {
    const numMatch = users.find((u) => Number(u.studentId) === asNum);
    if (numMatch) return numMatch.studentId;
  }
  return raw;
}

// Merge records saved under non-canonical ids into canonical ids
function migrateRecordsToCanonicalIds() {
  const records = readJson(RECORDS_PATH, {});
  const keys = Object.keys(records);
  if (!keys.length) return;
  let mutated = false;
  for (const oldId of keys) {
    const canonical = normalizeStudentId(oldId);
    if (canonical !== oldId) {
      const src = records[oldId] || {};
      const tgt = records[canonical] || { reportCards: [], punishments: [], images: [] };
      tgt.reportCards = [...(tgt.reportCards || []), ...(src.reportCards || [])];
      tgt.punishments = [...(tgt.punishments || []), ...(src.punishments || [])];
      tgt.images = [...(tgt.images || []), ...(src.images || [])];
      records[canonical] = tgt;
      delete records[oldId];
      mutated = true;
    }
  }
  if (mutated) writeJson(RECORDS_PATH, records);
}

// Seed defaults if files do not exist
if (!fs.existsSync(ANNOUNCEMENTS_PATH)) {
  writeJson(ANNOUNCEMENTS_PATH, [
    {
      id: 'ban-hairstyles',
      title: '禁止发型类型公告',
      content: '为维护良好校风，以下发型类型禁止出现：杀马特、海藻头、爆炸头、五颜六色渐变染等。请同学们遵守规定。',
      pinned: true,
      createdAt: Date.now()
    }
  ]);
}

if (!fs.existsSync(ARTICLES_PATH)) {
  writeJson(ARTICLES_PATH, [
    {
      id: 'welcome',
      title: '欢迎访问学校官网',
      content: '这里会发布学校新闻与公告，敬请关注。',
      createdAt: Date.now()
    }
  ]);
}

if (!fs.existsSync(USERS_PATH)) {
  // Fake parent accounts (studentId + password)
  writeJson(USERS_PATH, [
    { studentId: '20230001', password: '123456', name: '张三家长' },
    { studentId: '20230002', password: 'abcdef', name: '李四家长' }
  ]);
}

if (!fs.existsSync(RECORDS_PATH)) {
  // Minimal seed: one student has records, another has none
  writeJson(RECORDS_PATH, {
    '20230001': {
      reportCards: [
        { term: '2024-2025 上学期', chinese: 92, math: 95, english: 90, physics: 88, chemistry: 90 }
      ],
      punishments: [
        { date: '2025-03-10', type: '警告', reason: '上课讲话影响他人学习' }
      ],
      images: []
    },
    '20230002': {
      reportCards: [],
      punishments: [],
      images: []
    }
  });
}

if (!fs.existsSync(AUDIT_PATH)) {
  writeJson(AUDIT_PATH, []);
}

if (!fs.existsSync(SITE_PATH)) {
  // 站点设置：登录装饰与首页轮播
  writeJson(SITE_PATH, { logo: null, admissionBg: null, banners: [] });
}

if (!fs.existsSync(ADMINS_PATH)) {
  // Default admin list with one admin
  writeJson(ADMINS_PATH, [ { username: 'admin', password: 'admin123' } ]);
}

// View engine and middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// File upload setup (multer)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    const base = path.basename(file.originalname || 'image', ext).replace(/[^a-zA-Z0-9-_]/g, '_');
    const name = `${Date.now()}_${base}${ext}`;
    cb(null, name);
  }
});
const upload = multer({ storage });

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 8 }
  })
);

// One-time migrate any legacy non-canonical keys on startup
migrateRecordsToCanonicalIds();

// Auth helpers
function requireParent(req, res, next) {
  if (req.session && req.session.parent) return next();
  return res.redirect('/');
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.redirect('/login?role=admin');
}

// Routes - Public
app.get('/', (req, res) => {
  const announcementsRaw = readJson(ANNOUNCEMENTS_PATH, []);
  const articlesRaw = readJson(ARTICLES_PATH, []);
  const site = readJson(SITE_PATH, { logo: null, admissionBg: null, banners: [] });
  const announcements = [...announcementsRaw].sort((a, b) => {
    const pinDiff = Number(!!b.pinned) - Number(!!a.pinned);
    if (pinDiff !== 0) return pinDiff;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });
  const articles = [...articlesRaw].sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.render('home', {
    parent: req.session.parent || null,
    announcements,
    articles,
    site
  });
});

// Unified login page
app.get('/login', (req, res) => {
  const role = (req.query.role === 'admin') ? 'admin' : 'parent';
  const site = readJson(SITE_PATH, { logo: null, admissionBg: null, banners: [] });
  res.render('login', { role, error: null, site });
});

// Parent login
app.post('/login', (req, res) => {
  const { studentId, password } = req.body;
  const users = readJson(USERS_PATH, []);
  const user = users.find((u) => u.studentId === studentId && u.password === password);
  if (!user) {
    return res.status(401).render('login', { role: 'parent', error: '学号或密码错误' });
  }
  req.session.parent = { studentId: user.studentId, name: user.name };
  res.redirect('/records');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// Student records (parent only)
app.get('/records', requireParent, (req, res) => {
  const { studentId } = req.session.parent;
  const allRecords = readJson(RECORDS_PATH, {});
  const records = allRecords[studentId] || { reportCards: [], punishments: [], images: [], admissions: [] };
  res.render('records', { parent: req.session.parent, records });
});

// Admin routes (stored in admins.json)

app.get('/admin/login', (req, res) => {
  if (req.session.admin) return res.redirect('/admin');
  // 统一跳到新登录页（管理员角色）
  return res.redirect('/login?role=admin');
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  const admins = readJson(ADMINS_PATH, []);
  const ok = admins.find(a => a.username === username && a.password === password);
  if (ok) { req.session.admin = { username }; return res.redirect('/admin'); }
  res.status(401).render('admin/login', { error: '用户名或密码错误' });
});

// 注意：管理员新建仅允许在登录后的后台内进行（出于安全考虑），公共入口已移除。

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin', requireAdmin, (req, res) => {
  const announcements = readJson(ANNOUNCEMENTS_PATH, []);
  const articles = readJson(ARTICLES_PATH, []);
  const site = readJson(SITE_PATH, { logo: null, admissionBg: null, banners: [] });
  res.render('admin/dashboard', { admin: req.session.admin, announcements, articles, site });
});

// Admin: list uploaded files (debug/utility)
app.get('/admin/uploads', requireAdmin, (req, res) => {
  try {
    const files = fs.readdirSync(UPLOADS_DIR).filter((f) => !f.startsWith('.'));
    const items = files
      .map((name) => {
        const full = path.join(UPLOADS_DIR, name);
        const st = fs.statSync(full);
        return {
          name,
          url: `/uploads/${name}`,
          size: st.size,
          mtime: st.mtimeMs
        };
      })
      .sort((a, b) => b.mtime - a.mtime);
    res.render('admin/uploads', { items });
  } catch (e) {
    res.status(500).send('Failed to read uploads directory');
  }
});

// Admin: Announcements CRUD (MVP minimal)
app.post('/admin/announcements', requireAdmin, upload.single('annImage'), (req, res) => {
  const { title, content, pinned, imageUrl } = req.body;
  const announcements = readJson(ANNOUNCEMENTS_PATH, []);
  let img = (imageUrl || '').trim() || null;
  if (req.file && req.file.filename) img = `/uploads/${req.file.filename}`;
  const newItem = { id: String(Date.now()), title, content, pinned: Boolean(pinned), image: img, createdAt: Date.now() };
  announcements.unshift(newItem);
  writeJson(ANNOUNCEMENTS_PATH, announcements);
  appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'announcement.create', payload: { id: newItem.id, title, image: img } });
  res.redirect('/admin');
});

app.post('/admin/announcements/:id/delete', requireAdmin, (req, res) => {
  const { id } = req.params;
  const announcements = readJson(ANNOUNCEMENTS_PATH, []);
  const next = announcements.filter((a) => a.id !== id);
  writeJson(ANNOUNCEMENTS_PATH, next);
  appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'announcement.delete', payload: { id } });
  res.redirect('/admin');
});

// Admin: Articles CRUD (MVP minimal)
app.post('/admin/articles', requireAdmin, (req, res) => {
  const { title, content } = req.body;
  const articles = readJson(ARTICLES_PATH, []);
  const newItem = { id: String(Date.now()), title, content, createdAt: Date.now() };
  articles.unshift(newItem);
  writeJson(ARTICLES_PATH, articles);
   appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'article.create', payload: { id: newItem.id, title } });
  res.redirect('/admin');
});

app.post('/admin/articles/:id/delete', requireAdmin, (req, res) => {
  const { id } = req.params;
  const articles = readJson(ARTICLES_PATH, []);
  const next = articles.filter((a) => a.id !== id);
  writeJson(ARTICLES_PATH, next);
  appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'article.delete', payload: { id } });
  res.redirect('/admin');
});

// Admin: Add student records (report card or punishment)
app.post('/admin/records/add', requireAdmin, upload.any(), (req, res) => {
  const targetId = normalizeStudentId(req.body.studentId);
  let { type } = req.body;
  const allRecords = readJson(RECORDS_PATH, {});
  if (!allRecords[targetId]) {
    allRecords[targetId] = { reportCards: [], punishments: [], images: [], admissions: [] };
  }

  // 服务器兜底：若存在上传文件或填写了图片URL，则强制按图片档案处理
  const providedImageUrl = (req.body.imageUrl || '').trim();
  if (req.file || providedImageUrl) {
    type = 'image';
  }

  if (type === 'reportCard') {
    const { term, chinese, math, english, physics, chemistry } = req.body;
    allRecords[targetId].reportCards.unshift({
      term,
      chinese: Number(chinese),
      math: Number(math),
      english: Number(english),
      physics: Number(physics),
      chemistry: Number(chemistry)
    });
  } else if (type === 'punishment') {
    const { date, ptype, reason } = req.body;
    allRecords[targetId].punishments.unshift({ date, type: ptype, reason });
  } else if (type === 'image') {
    const { title, description } = req.body;
    let url = providedImageUrl ? providedImageUrl : null;
    const f = (req.files || []).find(f => f.fieldname === 'imageFile');
    if (f && f.filename) url = `/uploads/${f.filename}`;
    if (url) {
      if (!allRecords[targetId].images) allRecords[targetId].images = [];
      allRecords[targetId].images.unshift({
        id: String(Date.now()),
        title: title || '图片档案',
        description: description || '',
        url,
        uploadedAt: Date.now()
      });
      appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'record.add.image', payload: { studentId: targetId, url } });
    }
  } else if (type === 'admission') {
    let url = (req.body.admissionUrl || '').trim();
    const f = (req.files || []).find(f => f.fieldname === 'admissionFile');
    if (f && f.filename) url = `/uploads/${f.filename}`;
    if (url) {
      if (!allRecords[targetId].admissions) allRecords[targetId].admissions = [];
      allRecords[targetId].admissions.unshift({ id: String(Date.now()), title: req.body.admissionTitle || '录取通知书', url, uploadedAt: Date.now() });
    }
  }

  writeJson(RECORDS_PATH, allRecords);
  res.redirect('/admin');
});

// Admin: Students management routes
app.get('/admin/students', requireAdmin, (req, res) => {
  const users = readJson(USERS_PATH, []);
  res.render('admin/students', { users });
});

app.get('/admin/students/new', requireAdmin, (req, res) => {
  const nextId = generateNextStudentId();
  res.render('admin/student_new', { nextId });
});

app.get('/admin/students/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const allRecords = readJson(RECORDS_PATH, {});
  const records = allRecords[id] || { reportCards: [], punishments: [], images: [] };
  const users = readJson(USERS_PATH, []);
  const user = users.find((u) => u.studentId === id) || { studentId: id, name: '' };
  res.render('admin/student', { student: user, records });
});

app.post('/admin/students/create', requireAdmin, upload.any(), (req, res) => {
  const { password, name } = req.body;
  const users = readJson(USERS_PATH, []);
  const canonical = generateNextStudentId();
  users.push({ studentId: canonical, password: password || '123456', name: name || `${canonical}家长` });
  writeJson(USERS_PATH, users);

  const allRecords = readJson(RECORDS_PATH, {});
  if (!allRecords[canonical]) allRecords[canonical] = { reportCards: [], punishments: [], images: [], admissions: [] };

  // 兼容老表单：若存在 initType 等单项字段，则按旧逻辑追加一条
  if (typeof req.body.initType !== 'undefined') {
    const providedImageUrl = (req.body.initImageUrl || '').trim();
    if (req.body.initType === 'reportCard') {
      const { term, chinese, math, english, physics, chemistry } = req.body;
      allRecords[canonical].reportCards.unshift({ term, chinese: Number(chinese||0), math: Number(math||0), english: Number(english||0), physics: Number(physics||0), chemistry: Number(chemistry||0) });
    } else if (req.body.initType === 'punishment') {
      const { date, ptype, reason } = req.body;
      allRecords[canonical].punishments.unshift({ date, type: ptype, reason });
    } else if (req.body.initType === 'image') {
      let url = providedImageUrl || null;
      const f = (req.files || []).find(f => f.fieldname === 'initImageFile');
      if (f && f.filename) url = `/uploads/${f.filename}`;
      if (url) allRecords[canonical].images.unshift({ id: String(Date.now()), title: req.body.initTitle || '图片档案', description: req.body.initDesc || '', url, uploadedAt: Date.now() });
    }
  }

  // 新表单：records[n][type]=image|reportCard|punishment
  const records = req.body.records || [];
  // 将单对象情况规范为数组
  const normalizedRecords = Array.isArray(records) ? records : Object.keys(records).length ? Object.values(records) : [];

  for (let idx = 0; idx < normalizedRecords.length; idx++) {
    const rec = normalizedRecords[idx] || {};
    const type = rec.type;
    if (type === 'reportCard') {
      const term = rec.term || '';
      const chinese = Number(rec.chinese || 0);
      const math = Number(rec.math || 0);
      const english = Number(rec.english || 0);
      const physics = Number(rec.physics || 0);
      const chemistry = Number(rec.chemistry || 0);
      allRecords[canonical].reportCards.unshift({ term, chinese, math, english, physics, chemistry });
    } else if (type === 'punishment') {
      const date = rec.date || '';
      const ptype = rec.ptype || '';
      const reason = rec.reason || '';
      allRecords[canonical].punishments.unshift({ date, type: ptype, reason });
    } else if (type === 'image') {
      const title = rec.title || '图片档案';
      const description = rec.description || '';
      let url = (rec.imageUrl || '').trim() || null;
      // 匹配对应的文件字段名：records[<idx>][imageFile]
      const fieldName = `records[${idx}][imageFile]`;
      const f = (req.files || []).find(f => f.fieldname === fieldName);
      if (f && f.filename) url = `/uploads/${f.filename}`;
      if (url) {
        allRecords[canonical].images.unshift({ id: String(Date.now()), title, description, url, uploadedAt: Date.now() });
      }
    }
  }

  // 录取通知书（可选）
  {
    let url = (req.body.admissionUrl || '').trim();
    const f = (req.files || []).find(f => f.fieldname === 'admissionFile');
    if (f && f.filename) url = `/uploads/${f.filename}`;
    if (url) {
      if (!allRecords[canonical].admissions) allRecords[canonical].admissions = [];
      allRecords[canonical].admissions.unshift({ id: String(Date.now()), title: (req.body.admissionTitle || '录取通知书'), url, uploadedAt: Date.now() });
    }
  }

  writeJson(RECORDS_PATH, allRecords);

  appendAuditLog({ when: Date.now(), user: (req.session.admin && req.session.admin.username) || 'admin', type: 'student.create', payload: { studentId: canonical, name } });
  res.redirect('/admin/students');
});

// Admin: audit logs
app.get('/admin/logs', requireAdmin, (req, res) => {
  const logs = readJson(AUDIT_PATH, []);
  res.render('admin/logs', { logs });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


