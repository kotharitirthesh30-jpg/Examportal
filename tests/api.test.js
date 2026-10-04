import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, test } from 'node:test';
import { createApp, initializeDatabase } from '../server.js';

let db;
let server;
let baseUrl;

async function request(route, { token, method = 'GET', body } = {}) {
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { response, payload: await response.json() };
}

before(async () => {
  process.env.ADMIN_EMAIL = 'admin@test.example';
  process.env.ADMIN_PASSWORD = 'test-admin-password-4821';
  process.env.ADMIN_NAME = 'Test Admin';
  db = await initializeDatabase(':memory:');
  delete process.env.ADMIN_EMAIL;
  delete process.env.ADMIN_PASSWORD;
  delete process.env.ADMIN_NAME;
  const app = createApp({ db, jwtSecret: 'test-signing-secret-that-is-long-enough' });
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  db?.close();
});

test('registration, authorization, answer privacy, and server-side grading', async () => {
  const missingAuth = await request('/api/data');
  assert.equal(missingAuth.response.status, 401);

  const adminLogin = await request('/api/auth/login', {
    method: 'POST',
    body: { role: 'admin', identifier: 'admin@test.example', password: 'test-admin-password-4821' },
  });
  assert.equal(adminLogin.response.status, 200);
  assert.equal('password_hash' in adminLogin.payload.user, false);
  const adminToken = adminLogin.payload.token;

  const registration = await request('/api/auth/register', {
    method: 'POST',
    body: { name: 'Test Student', email: 'student@test.example', password: 'student-password-8123', studentId: 'S-100' },
  });
  assert.equal(registration.response.status, 201);

  const studentLogin = await request('/api/auth/login', {
    method: 'POST',
    body: { role: 'student', identifier: 'S-100', password: 'student-password-8123' },
  });
  assert.equal(studentLogin.response.status, 200);
  const studentToken = studentLogin.payload.token;

  const forbiddenExam = await request('/api/exams', {
    method: 'POST', token: studentToken, body: { name: 'Forbidden', subject: 'Testing' },
  });
  assert.equal(forbiddenExam.response.status, 403);

  const createdExam = await request('/api/exams', {
    method: 'POST', token: adminToken,
    body: { name: 'API Test', subject: 'Testing', duration: 10, totalMarks: 10, passPercent: 100 },
  });
  assert.equal(createdExam.response.status, 201);
  const examId = createdExam.payload.exam.id;

  const addedQuestion = await request(`/api/exams/${examId}/questions`, {
    method: 'POST', token: adminToken,
    body: { text: 'Which option is correct?', options: ['First', 'Second'], correct: 1 },
  });
  assert.equal(addedQuestion.response.status, 201);

  const published = await request(`/api/exams/${examId}/status`, {
    method: 'PATCH', token: adminToken, body: { status: 'published' },
  });
  assert.equal(published.response.status, 200);

  const studentData = await request('/api/data', { token: studentToken });
  const studentQuestion = studentData.payload.exams[0].questions[0];
  assert.equal('correct' in studentQuestion, false);

  const started = await request(`/api/exams/${examId}/attempts`, { method: 'POST', token: studentToken });
  assert.equal(started.response.status, 201);
  const attemptId = started.payload.attempt.id;

  const savedAnswer = await request(`/api/attempts/${attemptId}/answers`, {
    method: 'PATCH', token: studentToken, body: { questionIndex: 0, optionIndex: 1 },
  });
  assert.equal(savedAnswer.response.status, 200);

  const resumed = await request(`/api/exams/${examId}/attempts`, { method: 'POST', token: studentToken });
  assert.equal(resumed.payload.attempt.id, attemptId);
  assert.deepEqual(resumed.payload.attempt.answers, { 0: 1 });

  const submitted = await request(`/api/attempts/${attemptId}/submit`, {
    method: 'POST', token: studentToken, body: { score: 0, answers: { 0: 0 } },
  });
  assert.equal(submitted.response.status, 201);
  assert.equal(submitted.payload.result.score, 1);
  assert.equal(submitted.payload.result.percentage, 100);
  assert.equal(submitted.payload.result.passed, true);

  const duplicateSubmit = await request(`/api/attempts/${attemptId}/submit`, { method: 'POST', token: studentToken, body: {} });
  assert.equal(duplicateSubmit.payload.result.id, submitted.payload.result.id);

  const adminData = await request('/api/data', { token: adminToken });
  assert.equal(adminData.payload.exams[0].questions[0].correct, 1);
  assert.equal('password_hash' in adminData.payload.users[0], false);
  assert.equal(adminData.payload.results.length, 1);
});