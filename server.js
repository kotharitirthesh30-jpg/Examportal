import 'dotenv/config';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.dirname(fileURLToPath(import.meta.url));
const now = () => Date.now();

function publicUser(row) {
  return {
    id: row.id,
    role: row.role,
    name: row.name,
    email: row.email,
    studentId: row.student_id,
    department: row.department,
    createdAt: row.created_at,
  };
}

function parseExam(row, includeAnswers) {
  const questions = JSON.parse(row.questions_json);
  return {
    id: row.id,
    name: row.name,
    subject: row.subject,
    description: row.description,
    duration: row.duration,
    totalMarks: row.total_marks,
    passPercent: row.pass_percent,
    instructions: row.instructions,
    status: row.status,
    questions: includeAnswers ? questions : questions.map(({ correct, ...question }) => question),
    createdAt: row.created_at,
  };
}

function badRequest(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

export async function initializeDatabase(databasePath = process.env.DATABASE_PATH || path.join(projectRoot, 'data', 'orbit.sqlite')) {
  if (databasePath !== ':memory:') mkdirSync(path.dirname(path.resolve(databasePath)), { recursive: true });
  const db = new DatabaseSync(databasePath);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      role TEXT NOT NULL CHECK (role IN ('admin', 'student')),
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      student_id TEXT UNIQUE COLLATE NOCASE,
      department TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS exams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      subject TEXT NOT NULL,
      description TEXT NOT NULL,
      duration INTEGER NOT NULL,
      total_marks INTEGER NOT NULL,
      pass_percent INTEGER NOT NULL,
      instructions TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('draft', 'published')),
      questions_json TEXT NOT NULL DEFAULT '[]',
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attempts (
      id TEXT PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES exams(id),
      student_id TEXT NOT NULL REFERENCES users(id),
      started_at INTEGER NOT NULL,
      submitted_at INTEGER,
      answers_json TEXT,
      UNIQUE (exam_id, student_id, submitted_at)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS one_open_attempt_per_exam
      ON attempts (exam_id, student_id) WHERE submitted_at IS NULL;
    CREATE TABLE IF NOT EXISTS results (
      id TEXT PRIMARY KEY,
      attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id),
      student_id TEXT NOT NULL REFERENCES users(id),
      student_name TEXT NOT NULL,
      exam_id TEXT NOT NULL REFERENCES exams(id),
      exam_name TEXT NOT NULL,
      subject TEXT NOT NULL,
      score INTEGER NOT NULL,
      total_marks INTEGER NOT NULL,
      percentage INTEGER NOT NULL,
      passed INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      student_id TEXT NOT NULL REFERENCES users(id),
      student_name TEXT NOT NULL,
      exam_id TEXT NOT NULL REFERENCES exams(id),
      exam_name TEXT NOT NULL,
      reason TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);

  if (Boolean(process.env.ADMIN_EMAIL) !== Boolean(process.env.ADMIN_PASSWORD)) {
    throw new Error('Set both ADMIN_EMAIL and ADMIN_PASSWORD to seed the administrator account.');
  }
  if (process.env.ADMIN_EMAIL && !db.prepare("SELECT 1 FROM users WHERE role = 'admin'").get()) {
    if (process.env.ADMIN_PASSWORD.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
    const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('ADMIN_EMAIL must be a valid email address.');
    db.prepare(`INSERT INTO users (id, role, name, email, password_hash, department, created_at)
      VALUES (?, 'admin', ?, ?, ?, 'Administration', ?)`).run(
      randomUUID(), process.env.ADMIN_NAME?.trim() || 'Portal Administrator', email,
      await bcrypt.hash(process.env.ADMIN_PASSWORD, 12), now(),
    );
  }
  return db;
}

export function createApp({ db, jwtSecret = process.env.JWT_SECRET, allowedOrigins = process.env.ALLOWED_ORIGINS || 'https://kotharitirthesh30-jpg.github.io,http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000' } = {}) {
  if (!db) throw new Error('A database connection is required.');
  if (!jwtSecret || jwtSecret.length < 32) throw new Error('JWT_SECRET must be set to at least 32 characters.');
  const app = express();
  const origins = new Set(allowedOrigins.split(',').map(origin => origin.trim()).filter(Boolean));

  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
  app.use(cors({
    origin(origin, callback) {
      callback(null, !origin || origins.has(origin));
    },
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  }));
  app.use(express.json({ limit: '1mb' }));

  app.get('/', (req, res) => res.sendFile(path.join(projectRoot, 'index.html')));
  app.get('/index.html', (req, res) => res.sendFile(path.join(projectRoot, 'index.html')));
  app.get('/app.html', (req, res) => res.sendFile(path.join(projectRoot, 'app.html')));

  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
  const requireAuth = (req, res, next) => {
    const authorization = req.get('authorization') || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    try {
      const payload = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
      if (!user) throw new Error('Account no longer exists.');
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: 'Please sign in to continue.' });
    }
  };
  const requireRole = role => (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: 'You do not have permission to do that.' });
    next();
  };

  app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

  app.post('/api/auth/register', authLimiter, async (req, res, next) => {
    try {
      const { name, email, password, studentId = '', department = 'General' } = req.body || {};
      const normalizedEmail = String(email || '').trim().toLowerCase();
      if (!String(name || '').trim() || String(name).length > 100) throw badRequest('Enter a name of 1 to 100 characters.');
      if (!/^\S+@\S+\.\S+$/.test(normalizedEmail) || normalizedEmail.length > 254) throw badRequest('Enter a valid email address.');
      if (typeof password !== 'string' || password.length < 8 || password.length > 200) throw badRequest('Password must be at least 8 characters.');
      if (String(studentId).length > 60 || String(department).length > 100) throw badRequest('Student ID or department is too long.');
      const existing = db.prepare("SELECT 1 FROM users WHERE email = ? OR (? <> '' AND student_id = ?)").get(normalizedEmail, studentId, studentId);
      if (existing) throw badRequest('An account already exists with that email or student ID.', 409);
      const user = {
        id: randomUUID(), role: 'student', name: String(name).trim(), email: normalizedEmail,
        studentId: String(studentId).trim() || `STU-${randomUUID().slice(0, 8).toUpperCase()}`,
        department: String(department).trim() || 'General', createdAt: now(),
      };
      db.prepare(`INSERT INTO users (id, role, name, email, password_hash, student_id, department, created_at)
        VALUES (?, 'student', ?, ?, ?, ?, ?, ?)`).run(
        user.id, user.name, user.email, await bcrypt.hash(password, 12), user.studentId, user.department, user.createdAt,
      );
      res.status(201).json({ user });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/auth/login', authLimiter, async (req, res, next) => {
    try {
      const { role, identifier, password } = req.body || {};
      if (!['admin', 'student'].includes(role) || typeof identifier !== 'string' || typeof password !== 'string') {
        throw badRequest('Enter your account details.');
      }
      const value = identifier.trim();
      const user = db.prepare('SELECT * FROM users WHERE role = ? AND (email = ? COLLATE NOCASE OR student_id = ? COLLATE NOCASE)')
        .get(role, value, value);
      if (!user || !(await bcrypt.compare(password, user.password_hash))) throw badRequest('Invalid email or password.', 401);
      const token = jwt.sign({ sub: user.id, role: user.role }, jwtSecret, { algorithm: 'HS256', expiresIn: '12h' });
      res.json({ token, user: publicUser(user) });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/data', requireAuth, (req, res) => {
    const isAdmin = req.user.role === 'admin';
    const userId = req.user.id;
    const users = db.prepare(isAdmin
      ? 'SELECT * FROM users ORDER BY created_at DESC'
      : 'SELECT * FROM users WHERE id = ?').all(...(isAdmin ? [] : [userId])).map(publicUser);
    const examRows = db.prepare(isAdmin
      ? 'SELECT * FROM exams ORDER BY created_at DESC'
      : "SELECT * FROM exams WHERE status = 'published' ORDER BY created_at DESC").all();
    const attempts = db.prepare(isAdmin
      ? 'SELECT * FROM attempts ORDER BY started_at DESC'
      : 'SELECT * FROM attempts WHERE student_id = ? ORDER BY started_at DESC').all(...(isAdmin ? [] : [userId]));
    const results = db.prepare(isAdmin
      ? 'SELECT * FROM results ORDER BY created_at DESC'
      : 'SELECT * FROM results WHERE student_id = ? ORDER BY created_at DESC').all(...(isAdmin ? [] : [userId]));
    const notifications = isAdmin ? db.prepare('SELECT * FROM notifications ORDER BY created_at DESC').all() : [];

    res.json({
      currentUser: publicUser(req.user),
      users,
      exams: examRows.map(row => parseExam(row, isAdmin)),
      attempts: attempts.map(row => ({
        id: row.id, examId: row.exam_id, studentId: row.student_id,
        startedAt: row.started_at, submittedAt: row.submitted_at,
      })),
      results: results.map(formatResult),
      notifications: notifications.map(row => ({
        id: row.id, type: row.type, studentId: row.student_id, studentName: row.student_name,
        examId: row.exam_id, examName: row.exam_name, reason: row.reason,
        message: row.message, createdAt: row.created_at,
      })),
    });
  });

  app.post('/api/exams', requireAuth, requireRole('admin'), (req, res, next) => {
    try {
      const { name, subject, description = '', duration = 60, totalMarks = 100, passPercent = 40, instructions = '' } = req.body || {};
      if (!String(name || '').trim() || !String(subject || '').trim()) throw badRequest('Exam name and subject are required.');
      const values = [Number(duration), Number(totalMarks), Number(passPercent)];
      if (!Number.isInteger(values[0]) || values[0] < 1 || values[0] > 600) throw badRequest('Duration must be between 1 and 600 minutes.');
      if (!Number.isInteger(values[1]) || values[1] < 1 || values[1] > 100000) throw badRequest('Total marks must be a positive integer.');
      if (!Number.isInteger(values[2]) || values[2] < 0 || values[2] > 100) throw badRequest('Pass percentage must be between 0 and 100.');
      const exam = {
        id: randomUUID(), name: String(name).trim(), subject: String(subject).trim(),
        description: String(description).slice(0, 2000), duration: values[0], totalMarks: values[1],
        passPercent: values[2], instructions: String(instructions).slice(0, 4000), status: 'draft', questions: [], createdAt: now(),
      };
      db.prepare(`INSERT INTO exams (id, name, subject, description, duration, total_marks, pass_percent, instructions, status, questions_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', '[]', ?)`).run(
        exam.id, exam.name, exam.subject, exam.description, exam.duration, exam.totalMarks,
        exam.passPercent, exam.instructions, exam.createdAt,
      );
      res.status(201).json({ exam });
    } catch (error) {
      next(error);
    }
  });

  app.patch('/api/exams/:examId/status', requireAuth, requireRole('admin'), (req, res, next) => {
    try {
      const { status } = req.body || {};
      if (!['draft', 'published'].includes(status)) throw badRequest('Status must be draft or published.');
      const exam = db.prepare('SELECT questions_json FROM exams WHERE id = ?').get(req.params.examId);
      if (!exam) throw badRequest('Exam not found.', 404);
      if (status === 'published' && !JSON.parse(exam.questions_json).length) throw badRequest('Add at least one question before publishing.');
      const result = db.prepare('UPDATE exams SET status = ? WHERE id = ?').run(status, req.params.examId);
      res.json({ status });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/exams/:examId/questions', requireAuth, requireRole('admin'), (req, res, next) => {
    try {
      const row = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.examId);
      if (!row) throw badRequest('Exam not found.', 404);
      if (row.status === 'published') throw badRequest('Unpublish this exam before changing its questions.', 409);
      const { text, options, correct } = req.body || {};
      if (!String(text || '').trim() || String(text).length > 2000) throw badRequest('Question text is required and must be under 2,000 characters.');
      if (!Array.isArray(options) || options.length < 2 || options.length > 8 || options.some(option => typeof option !== 'string' || !option.trim())) {
        throw badRequest('Provide between 2 and 8 non-empty answer options.');
      }
      if (!Number.isInteger(correct) || correct < 0 || correct >= options.length) throw badRequest('Choose one correct option.');
      const question = { id: randomUUID(), text: String(text).trim(), options: options.map(option => option.trim()), correct };
      const questions = JSON.parse(row.questions_json);
      questions.push(question);
      db.prepare('UPDATE exams SET questions_json = ? WHERE id = ?').run(JSON.stringify(questions), row.id);
      res.status(201).json({ question });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/exams/:examId/attempts', requireAuth, requireRole('student'), (req, res, next) => {
    try {
      const exam = db.prepare("SELECT * FROM exams WHERE id = ? AND status = 'published'").get(req.params.examId);
      if (!exam) throw badRequest('This exam is not available.', 404);
      if (!JSON.parse(exam.questions_json).length) throw badRequest('This exam is not ready for attempts.', 409);
      const existing = db.prepare('SELECT * FROM attempts WHERE exam_id = ? AND student_id = ? AND submitted_at IS NULL')
        .get(exam.id, req.user.id);
      if (existing) return res.json({ attempt: {
        id: existing.id, examId: existing.exam_id, startedAt: existing.started_at,
        answers: existing.answers_json ? JSON.parse(existing.answers_json) : {},
      } });
      const attempt = { id: randomUUID(), examId: exam.id, studentId: req.user.id, startedAt: now() };
      db.prepare('INSERT INTO attempts (id, exam_id, student_id, started_at) VALUES (?, ?, ?, ?)')
        .run(attempt.id, attempt.examId, attempt.studentId, attempt.startedAt);
      res.status(201).json({ attempt: { ...attempt, answers: {} } });
    } catch (error) {
      next(error);
    }
  });

  app.patch('/api/attempts/:attemptId/answers', requireAuth, requireRole('student'), (req, res, next) => {
    try {
      const attempt = db.prepare('SELECT * FROM attempts WHERE id = ? AND student_id = ? AND submitted_at IS NULL')
        .get(req.params.attemptId, req.user.id);
      if (!attempt) throw badRequest('Active attempt not found.', 404);
      const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(attempt.exam_id);
      if (now() > attempt.started_at + exam.duration * 60_000 + 30_000) throw badRequest('The exam time has expired.', 410);
      const questions = JSON.parse(exam.questions_json);
      const questionIndex = Number(req.body?.questionIndex);
      const optionIndex = Number(req.body?.optionIndex);
      if (!Number.isInteger(questionIndex) || questionIndex < 0 || questionIndex >= questions.length) throw badRequest('Question not found.');
      if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex >= questions[questionIndex].options.length) throw badRequest('Answer option not found.');
      const answers = attempt.answers_json ? JSON.parse(attempt.answers_json) : {};
      answers[questionIndex] = optionIndex;
      db.prepare('UPDATE attempts SET answers_json = ? WHERE id = ?').run(JSON.stringify(answers), attempt.id);
      res.json({ answers });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/attempts/:attemptId/integrity-events', requireAuth, requireRole('student'), (req, res, next) => {
    try {
      const attempt = db.prepare('SELECT * FROM attempts WHERE id = ? AND student_id = ? AND submitted_at IS NULL')
        .get(req.params.attemptId, req.user.id);
      if (!attempt) throw badRequest('Active attempt not found.', 404);
      const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(attempt.exam_id);
      const reason = String(req.body?.reason || '').trim().slice(0, 500);
      if (!reason) throw badRequest('An integrity event reason is required.');
      const createdAt = now();
      db.prepare(`INSERT INTO notifications (id, type, student_id, student_name, exam_id, exam_name, reason, message, created_at)
        VALUES (?, 'exam-integrity', ?, ?, ?, ?, ?, ?, ?)`).run(
        randomUUID(), req.user.id, req.user.name, exam.id, exam.name, reason,
        `${req.user.name} triggered an exam integrity alert during ${exam.name}: ${reason}`, createdAt,
      );
      res.status(201).json({ createdAt });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/attempts/:attemptId/submit', requireAuth, requireRole('student'), (req, res, next) => {
    try {
      const attempt = db.prepare('SELECT * FROM attempts WHERE id = ? AND student_id = ?')
        .get(req.params.attemptId, req.user.id);
      if (!attempt) throw badRequest('Attempt not found.', 404);
      const previous = db.prepare('SELECT * FROM results WHERE attempt_id = ?').get(attempt.id);
      if (previous) return res.json({ result: formatResult(previous) });
      const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(attempt.exam_id);
      const questions = JSON.parse(exam.questions_json);
      if (!questions.length) throw badRequest('This exam has no questions.');
      if (now() > attempt.started_at + exam.duration * 60_000 + 30_000) throw badRequest('The exam time has expired.', 410);
      const answers = attempt.answers_json ? JSON.parse(attempt.answers_json) : {};
      const score = questions.reduce((total, question, index) => total + (Number(answers[index]) === question.correct ? 1 : 0), 0);
      const percentage = Math.round((score / questions.length) * 100);
      const result = {
        id: randomUUID(), attemptId: attempt.id, studentId: req.user.id, studentName: req.user.name,
        examId: exam.id, examName: exam.name, subject: exam.subject, score, totalMarks: exam.total_marks,
        percentage, passed: percentage >= exam.pass_percent, createdAt: now(),
      };
      db.exec('BEGIN');
      try {
        db.prepare('UPDATE attempts SET submitted_at = ?, answers_json = ? WHERE id = ?')
          .run(result.createdAt, JSON.stringify(answers), attempt.id);
        db.prepare(`INSERT INTO results (id, attempt_id, student_id, student_name, exam_id, exam_name, subject, score, total_marks, percentage, passed, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
          result.id, result.attemptId, result.studentId, result.studentName, result.examId, result.examName,
          result.subject, result.score, result.totalMarks, result.percentage, Number(result.passed), result.createdAt,
        );
        db.exec('COMMIT');
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
      res.status(201).json({ result });
    } catch (error) {
      next(error);
    }
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found.' }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That account or record already exists.' });
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error(error);
    res.status(status).json({ error: status >= 500 ? 'The server could not complete that request.' : error.message });
  });

  return app;
}

function formatResult(row) {
  return {
    id: row.id, attemptId: row.attempt_id, studentId: row.student_id, studentName: row.student_name,
    examId: row.exam_id, examName: row.exam_name, subject: row.subject, score: row.score,
    totalMarks: row.total_marks, percentage: row.percentage, passed: Boolean(row.passed), createdAt: row.created_at,
  };
}

async function startServer() {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret || jwtSecret.length < 32) throw new Error('Set JWT_SECRET to a random value of at least 32 characters.');
  const db = await initializeDatabase();
  const app = createApp({ db, jwtSecret });
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => console.log(`Orbit API listening on port ${port}`));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startServer().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}