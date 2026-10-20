'use strict';

/**
 * Verification suite for the merged server.
 * Runs your original server.js contract against an in-memory MongoDB.
 *
 *   npm test
 */

const assert = require('node:assert/strict');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret-not-for-production';
process.env.LOGIN_RATE_LIMIT_MAX = '1000';

const ACCESS_ID = 'TS-1001';
const PASSWORD = 'correct horse battery staple';

let mongo;
const servers = [];

function cookiesFrom(res) {
  const raw = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  return raw.map((c) => c.split(';')[0]).join('; ');
}

function client(base) {
  return {
    post(path, body, cookie) {
      const headers = { 'Content-Type': 'application/json' };
      if (cookie) headers.Cookie = cookie;
      return fetch(base + path, { method: 'POST', headers, body: JSON.stringify(body) });
    },
    get(path, cookie) {
      return fetch(base + path, {
        headers: cookie ? { Cookie: cookie, Accept: 'application/json' } : { Accept: 'application/json' },
        redirect: 'manual',
      });
    },
  };
}

function listen(app) {
  const server = app.listen(0);
  servers.push(server);
  return new Promise((resolve) => {
    server.once('listening', () => resolve('http://127.0.0.1:' + server.address().port));
  });
}

async function run() {
  mongo = await MongoMemoryServer.create();
  const uri = mongo.getUri('trustsam_merge_test');
  process.env.MONGO_URI = uri;

  const { app, connect, User, Transfer } = require('../server');
  await connect(uri);

  await User.create({ accessId: ACCESS_ID, password: await bcrypt.hash(PASSWORD, 10), name: 'Sam', totalBalance: 12500 });

  const base = await listen(app);
  const api = client(base);
  console.log('merged server on', base, '\n');

  const checks = [];
  const check = (name, fn) => checks.push({ name, fn });

  /* original contract */
  check('POST /login with accessId → {success:true}', async () => {
    const res = await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD });
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal(body.success, true);
  });

  check('POST /login accepts the email field from the new page', async () => {
    const res = await api.post('/login', { email: ACCESS_ID, password: PASSWORD });
    assert.equal(res.status, 200);
  });

  check('wrong password → 401 with the original message', async () => {
    const res = await api.post('/login', { accessId: ACCESS_ID, password: 'wrong' });
    const body = await res.json();
    assert.equal(res.status, 401);
    assert.equal(body.message, 'Incorrect Access ID or Passcode.');
  });

  check('missing fields → 400 with the original message', async () => {
    const res = await api.post('/login', { accessId: '', password: '' });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.equal(body.message, 'Access ID and Passcode are required.');
  });

  /* session */
  check('login sets an httpOnly sessionId cookie', async () => {
    const res = await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD });
    const raw = res.headers.getSetCookie ? res.headers.getSetCookie().join(';') : '';
    assert.ok(raw.includes('sessionId='), 'cookie name changed');
    assert.match(raw, /httponly/i);
  });

  check('GET /check-session → {loggedIn:true}', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const body = await (await api.get('/check-session', cookie)).json();
    assert.equal(body.loggedIn, true);
  });

  check('/check-session without a cookie → 401', async () => {
    const res = await api.get('/check-session');
    assert.equal(res.status, 401);
  });

  check('session survives and is readable (server-side store, not memory)', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const stored = await mongoose.connection.collection('sessions').countDocuments();
    assert.ok(stored > 0, 'no document in the sessions collection');
    const res = await api.get('/dashboard', cookie);
    assert.equal(res.status, 200);
  });

  /* guarded API */
  for (const path of ['/dashboard', '/balance', '/get-transfers']) {
    check(`GET ${path} without a session → 401`, async () => {
      const res = await api.get(path);
      assert.equal(res.status, 401);
    });
  }

  check('POST /save-transfer without a session → 401', async () => {
    const res = await api.post('/save-transfer', { amount: '10' });
    assert.equal(res.status, 401);
  });

  /* dashboard + balance shapes preserved */
  check('GET /dashboard keeps {accessId,totalBalance,name}', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const body = await (await api.get('/dashboard', cookie)).json();
    assert.deepEqual(Object.keys(body).sort(), ['accessId', 'name', 'totalBalance']);
    assert.equal(body.accessId, ACCESS_ID);
    assert.equal(body.totalBalance, 12500);
    assert.equal(body.name, 'Sam');
  });

  check('GET /balance keeps {totalBalance}', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const body = await (await api.get('/balance', cookie)).json();
    assert.deepEqual(body, { totalBalance: 12500 });
  });

  /* transfers */
  check('POST /save-transfer stores it, forces status=Processing', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const res = await api.post(
      '/save-transfer',
      { amount: '250.00', bankName: 'Test Bank', toAccount: '12345678', status: 'Completed' },
      cookie
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.match(body.transactionId, /^TRX-[0-9A-F]{8}$/);

    const saved = await Transfer.findOne({ transactionId: body.transactionId });
    assert.equal(saved.status, 'Processing', 'client-supplied status was trusted');
    assert.equal(saved.userAccessId, ACCESS_ID);
  });

  check('POST /save-transfer cannot inject userAccessId', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const res = await api.post(
      '/save-transfer',
      { amount: '1', userAccessId: 'SOMEONE-ELSE', transactionId: 'TRX-FORGED09' },
      cookie
    );
    const body = await res.json();
    const saved = await Transfer.findOne({ transactionId: body.transactionId });
    assert.equal(saved.userAccessId, ACCESS_ID);
    assert.notEqual(saved.transactionId, 'TRX-FORGED09');
  });

  check('GET /get-transfers returns newest first, scoped to the user', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const list = await (await api.get('/get-transfers', cookie)).json();
    assert.ok(Array.isArray(list) && list.length >= 2);
    assert.ok(list.every((t) => t.userAccessId === ACCESS_ID));
    for (let i = 1; i < list.length; i += 1) {
      assert.ok(new Date(list[i - 1].createdAt) >= new Date(list[i].createdAt), 'not sorted desc');
    }
  });

  /* legacy plaintext migration */
  check('legacy plaintext password still logs in, then becomes a bcrypt hash', async () => {
    await User.create({ accessId: 'LEGACY-1', password: 'plaintext-pass', name: 'Old', totalBalance: 0 });
    const before = await User.findOne({ accessId: 'LEGACY-1' });
    assert.equal(before.password, 'plaintext-pass');

    const res = await api.post('/login', { accessId: 'LEGACY-1', password: 'plaintext-pass' });
    assert.equal(res.status, 200);

    const after = await User.findOne({ accessId: 'LEGACY-1' });
    assert.match(after.password, /^\$2[aby]\$/, 'password was not upgraded');
    assert.equal(await bcrypt.compare('plaintext-pass', after.password), true);

    const again = await api.post('/login', { accessId: 'LEGACY-1', password: 'plaintext-pass' });
    assert.equal(again.status, 200, 'second login after migration failed');
  });

  /* page guards — the original hole */
  for (const path of ['/account', '/transfer', '/deposit', '/messages', '/more']) {
    check(`GET ${path} without a session → redirect to /login`, async () => {
      const res = await api.get(path);
      assert.equal(res.status, 302);
      assert.equal(res.headers.get('location'), '/login');
    });
  }

  check('GET /account WITH a session → 200', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const res = await api.get('/account', cookie);
    assert.equal(res.status, 200);
    assert.ok((await res.text()).includes('Your account'));
  });

  check('GET /login WITH a session → redirect to /account', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const res = await api.get('/login', cookie);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/account');
  });

  /* logout */
  check('POST /logout then /check-session → 401', async () => {
    const cookie = cookiesFrom(await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD }));
    const out = await api.post('/logout', {}, cookie);
    assert.equal(out.status, 200);
    const res = await api.get('/check-session', cookie);
    assert.equal(res.status, 401);
  });

  /* hygiene */
  check('no bcrypt hash or password echoed in any login response', async () => {
    const res = await api.post('/login', { accessId: ACCESS_ID, password: PASSWORD });
    const text = await res.text();
    assert.ok(!text.includes('$2'), 'hash leaked');
    assert.ok(!/correct horse/i.test(text), 'password echoed');
  });

  check('next() route unknown paths → 404 for API, plain 404 for pages', async () => {
    const apiRes = await api.get('/dashboard/nope');
    assert.equal(apiRes.status, 404);
    const pageRes = await fetch(base + '/nope-page', { redirect: 'manual' });
    assert.equal(pageRes.status, 404);
  });

  let failed = 0;
  for (const { name, fn } of checks) {
    try {
      await fn();
      console.log('  PASS  ' + name);
    } catch (err) {
      failed += 1;
      console.log('  FAIL  ' + name + ' → ' + err.message);
    }
  }

  console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
  return failed;
}

run()
  .then(async (failed) => {
    for (const s of servers) await new Promise((r) => s.close(r)).catch(() => {});
    await mongoose.disconnect().catch(() => {});
    if (mongo) await mongo.stop();
    process.exit(failed ? 1 : 0);
  })
  .catch(async (err) => {
    console.error('harness error:', err);
    for (const s of servers) await new Promise((r) => s.close(r)).catch(() => {});
    if (mongo) await mongo.stop().catch(() => {});
    process.exit(1);
  });
