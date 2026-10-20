require('dns').setServers(['8.8.8.8', '1.1.1.1']);

'use strict';

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 9001;
const IS_PROD = process.env.NODE_ENV === 'production';
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_MINUTES = Number(process.env.SESSION_MINUTES) || 30;
const BCRYPT_ROUNDS = 12;

const mongoURI = process.env.MONGO_URI || process.env.MONGODB_URI;
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (IS_PROD ? null : crypto.randomBytes(32).toString('hex'));

if (!SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set in production.');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');

async function connect(uri = mongoURI) {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!uri) {
    throw new Error('Add MONGO_URI to your .env file.');
  }

  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });

  console.log(
    `[MongoDB] Connected to ${mongoose.connection.host}/${mongoose.connection.name}`
  );

  return mongoose.connection;
}

/* ------------------------------ Schemas ------------------------------ */

// Email is the only sign-in identifier.
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    unique: true,
    sparse: true
  },
  password: {
    type: String,
    required: true
  },
  totalBalance: {
    type: Number,
    default: 0
  },
  name: {
    type: String,
    default: ''
  }
});

const User =
  mongoose.models.User || mongoose.model('User', userSchema);

// Keep userAccessId as the stored field name so existing transfer records
// and the current transfer collection are not renamed. It stores the email.
const transferSchema = new mongoose.Schema({
  userAccessId: String,
  transactionId: String,
  fromAccount: String,
  toAccount: String,
  status: String,
  bankName: String,
  amount: String,
  description: String,
  frequency: String,
  createdAt: { type: Date, default: Date.now }
});

const Transfer =
  mongoose.models.Transfer ||
  mongoose.model('Transfer', transferSchema);

/* ----------------------------- Middleware ---------------------------- */

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: IS_PROD ? { maxAge: 15552000, includeSubDomains: true } : false
  })
);

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true
  })
);

app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(cookieParser());

app.use(
  session({
    name: 'sessionId',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: mongoURI,
      collectionName: 'sessions',
      ttl: SESSION_MINUTES * 60
    }),
    cookie: {
      httpOnly: true,
      sameSite: process.env.COOKIE_SAMESITE || 'lax',
      secure: IS_PROD || process.env.COOKIE_SAMESITE === 'none',
      maxAge: SESSION_MINUTES * 60 * 1000
    }
  })
);

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => (err ? reject(err) : resolve()));
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(err => (err ? reject(err) : resolve()));
  });
}

function requireLogin(req, res, next) {
  if (req.session && req.session.email) return next();

  return res.status(401).json({
    success: false,
    error: 'Please log in first.'
  });
}

function requireLoginPage(req, res, next) {
  if (req.session && req.session.email) return next();
  return res.redirect('/login');
}

function noStore(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
}

// Prevent direct access to protected page files by filename.
app.use((req, res, next) => {
  if (req.path === '/index.html') return res.redirect('/');
  if (req.path === '/login.html') return res.redirect('/login');
  next();
});

// Keep assets such as images and CSS available.
app.use(express.static(PUBLIC_DIR, {
  index: false,
  maxAge: IS_PROD ? '1h' : 0
}));

/* ---------------------------- Rate Limits ---------------------------- */

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many attempts. Please wait and try again.'
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many registration attempts. Please try again later.'
  }
});

function wantsHtmlForm(req) {
  return (
    req.is('application/x-www-form-urlencoded') &&
    !req.headers['x-requested-with']
  );
}

function sendAuthSuccess(req, res, message) {
  if (wantsHtmlForm(req)) {
    return res.redirect(303, '/');
  }

  return res.json({
    success: true,
    message,
    redirect: '/'
  });
}

/* --------------------------- Registration ---------------------------- */

// New users register using email and password.
// POST /register
app.post('/register', registerLimiter, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = typeof req.body?.password === 'string'
    ? req.body.password
    : '';
  const name = String(req.body?.name || '').trim().slice(0, 100);

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required.'
    });
  }

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    password.length < 8 ||
    password.length > 200
  ) {
    return res.status(400).json({
      success: false,
      message: 'Enter a valid email and a password of at least 8 characters.'
    });
  }

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with that email already exists. Please log in.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      totalBalance: 0
    });

    await regenerateSession(req);
    req.session.email = user.email;
    req.session.name = user.name || '';
    await saveSession(req);

    return sendAuthSuccess(req, res, 'Account created successfully.');
  } catch (err) {
    // Handles duplicate-email races without exposing database details.
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'An account with that email already exists. Please log in.'
      });
    }

    console.error('[Registration Error]', err.message);

    return res.status(500).json({
      success: false,
      message: 'Could not create the account. Please try again.'
    });
  }
});

/* ------------------------------- Login ------------------------------- */

// Existing users sign in using email and password.
// POST /login
app.post('/login', loginLimiter, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = typeof req.body?.password === 'string'
    ? req.body.password
    : '';

  if (!email || !password || email.length > 254 || password.length > 200) {
    return res.status(400).json({
      success: false,
      message: 'Enter your email and password.'
    });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect email or password.'
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.password);

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect email or password.'
      });
    }

    await regenerateSession(req);
    req.session.email = user.email;
    req.session.name = user.name || '';
    await saveSession(req);

    return sendAuthSuccess(req, res, 'Login successful.');
  } catch (err) {
    console.error('[Login Error]', err.message);

    return res.status(500).json({
      success: false,
      message: 'Server error during login.'
    });
  }
});

/* ------------------------- Session and Logout ------------------------ */

app.get('/check-session', (req, res) => {
  if (req.session?.email) {
    return res.json({
      loggedIn: true,
      email: req.session.email,
      name: req.session.name || ''
    });
  }

  return res.status(401).json({ loggedIn: false });
});

app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.json({ success: true });
  }

  req.session.destroy(err => {
    if (err) {
      console.error('[Logout Error]', err.message);
      return res.status(500).json({
        success: false,
        error: 'Could not sign out.'
      });
    }

    res.clearCookie('sessionId');
    return res.json({ success: true, redirect: '/login' });
  });
});

/* ------------------------------ Transfers ---------------------------- */

app.post('/save-transfer', requireLogin, async (req, res) => {
  try {
    const b = req.body || {};

    const newTransfer = new Transfer({
      fromAccount: b.fromAccount,
      toAccount: b.toAccount,
      bankName: b.bankName,
      amount: b.amount,
      description: b.description,
      frequency: b.frequency,
      transactionId: `TRX-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
      userAccessId: req.session.email,
      status: 'Processing'
    });

    await newTransfer.save();

    return res.json({
      success: true,
      transactionId: newTransfer.transactionId
    });
  } catch (err) {
    console.error('[Save Transfer Error]', err.message);

    return res.status(500).json({
      success: false,
      error: 'Failed to save transfer.'
    });
  }
});

app.get('/get-transfers', requireLogin, async (req, res) => {
  try {
    const transfers = await Transfer.find({
      userAccessId: req.session.email
    }).sort({ createdAt: -1 });

    return res.json(transfers);
  } catch (err) {
    console.error('[Get Transfers Error]', err.message);

    return res.status(500).json({
      error: 'Failed to fetch transfers.'
    });
  }
});

/* --------------------------- Dashboard Data -------------------------- */

app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.session.email });

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.json({
      email: user.email,
      totalBalance: user.totalBalance,
      name: user.name
    });
  } catch (err) {
    console.error('[Dashboard Error]', err.message);

    return res.status(500).json({
      error: 'Failed to load dashboard.'
    });
  }
});

app.get('/balance', requireLogin, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.session.email });

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.json({ totalBalance: user.totalBalance });
  } catch (err) {
    console.error('[Balance Error]', err.message);

    return res.status(500).json({
      error: 'Failed to load balance.'
    });
  }
});

/* -------------------------------- Pages ------------------------------ */

// The dashboard is public/index.html, but only signed-in users can see it.
app.get('/', (req, res) => {
  if (!req.session?.email) {
    return res.redirect(302, '/login');
  }

  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session?.email) {
    return res.redirect(302, '/');
  }

  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

// Keep /account working for any existing links in the app.
app.get('/account', requireLoginPage, (req, res) => {
  return res.redirect(302, '/');
});

app.get('/transfer', requireLoginPage, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'transfer.html'));
});

app.get('/deposit', requireLoginPage, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'deposit.html'));
});

app.get('/messages', requireLoginPage, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'messages.html'));
});

app.get('/more', requireLoginPage, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(PUBLIC_DIR, 'more.html'));
});

/* ------------------------------- Errors ------------------------------ */

app.use((req, res) => {
  const isApi = /^\/(login|register|logout|check-session|save-transfer|get-transfers|dashboard|balance)(\/|$)/.test(req.path);

  if (isApi) {
    return res.status(404).json({
      success: false,
      error: 'Not found.'
    });
  }

  return res.status(404).send('Page not found.');
});

app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;

  if (status >= 500) {
    console.error('[Server Error]', err.message);
  }

  if (res.headersSent) return next(err);

  return res.status(status).json({
    success: false,
    error: status === 400
      ? 'That request could not be read.'
      : 'Something went wrong.'
  });
});

/* -------------------------------- Start ------------------------------ */

async function main() {
  await connect();

  return app.listen(PORT, () => {
    console.log(`[TrustSam] Server running on port ${PORT}`);
  });
}

if (require.main === module) {
  main().catch(err => {
    console.error('[Startup Error]', err.message);
    process.exit(1);
  });
}

module.exports = { app, main, connect, User, Transfer };