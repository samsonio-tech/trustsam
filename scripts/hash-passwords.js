n'use strict';

/**
 * One-off maintenance script: hash every plaintext password already in the
 * database, so you don't have to wait for each user to sign in.
 *
 *   node scripts/hash-passwords.js          # dry run, reports what it would do
 *   node scripts/hash-passwords.js --apply  # actually writes
 *
 * The server also migrates a record on successful sign-in, so this is optional.
 */

require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const MONGODB_URI = process.env.MONGO_URI || process.env.MONGODB_URI;
const BCRYPT_RE = /^\$2[aby]\$/;
const APPLY = process.argv.includes('--apply');

async function run() {
  if (!MONGODB_URI) {
    console.error('MONGO_URI is not set.');
    process.exit(1);
  }

  await mongoose.connect(MONGODB_URI);
  const users = mongoose.connection.collection('users');

  const all = await users.find({}).project({ accessId: 1, password: 1 }).toArray();
  const plaintext = all.filter((u) => typeof u.password === 'string' && u.password && !BCRYPT_RE.test(u.password));

  console.log(`${all.length} user(s) found, ${plaintext.length} with a plaintext password.`);

  if (!plaintext.length) {
    console.log('Nothing to do.');
    await mongoose.disconnect();
    return;
  }

  for (const u of plaintext) {
    const hash = await bcrypt.hash(u.password, 12);
    if (APPLY) {
      await users.updateOne({ _id: u._id }, { $set: { password: hash } });
      console.log(`  hashed  ${u.accessId}`);
    } else {
      console.log(`  would hash  ${u.accessId}`);
    }
  }

  console.log(APPLY ? 'Done.' : 'Dry run only. Re-run with --apply to write.');
  await mongoose.disconnect();
}

run().catch(async (err) => {
  console.error('[fail]', err.message);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
