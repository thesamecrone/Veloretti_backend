const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('./db');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { registerUser } = require('./auth');

require('dotenv').config();
const app = express();
app.set('trust proxy', 1);

app.use(cors({
  origin: 'https://thesamecrone.github.io',
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'none'
  }
}));

const checkUserStatus = async (req, res, next) => {
  if (req.path === '/api/register' || req.path === '/auth/google/callback' || req.path === '/') {
    return next();
  }

  if (!req.user) {
    console.log("DEBUG: req.user is:", req.user);
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const result = await pool.query('SELECT status FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user || user.status === 'blocked') {
      req.logout(() => { });
      return res.status(403).json({ message: "User is blocked" });
    }
    next();
  } catch (err) {
    res.status(500).json({ message: "Database error" });
  }
};

app.use(passport.initialize());
app.use(passport.session());
app.use(checkUserStatus);

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_REDIRECT_URI
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      const name = profile.displayName;

      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      let user = result.rows[0];

      if (!user) {
        const insert = await pool.query(
          'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *',
          [name, email]
        );
        user = insert.rows[0];
      }

      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

app.get('/', (req, res) => {
  res.send('It works!');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    req.session.save(() => {
      const user = { name: req.user.name, email: req.user.email };

      res.send(`
        <script>
          window.opener.postMessage({ type: 'GOOGLE_AUTH_SUCCESS', user: ${JSON.stringify(user)} }, '*');
          window.close();
        </script>
        <p>Authentication successful! You can close this window.</p>
      `);
    });
  }
);

app.post('/api/subscribe', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const existing = await pool.query(
      "SELECT * FROM subscriptions WHERE email = $1",
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "Email already subscribed" });
    }

    await pool.query(
      "INSERT INTO subscriptions(email) VALUES($1)",
      [email]
    );

    res.json({ message: "Subscribed successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = await registerUser(name, email, passwordHash);

    res.status(201).json({ message: "User registered successfully", user: newUser });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: "Email already exists" });
    }
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, status, last_login FROM users ORDER BY last_login DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

app.post('/api/users/block', async (req, res) => {
  const { ids } = req.body;
  await pool.query("UPDATE users SET status = 'blocked' WHERE id = ANY($1)", [ids]);
  res.sendStatus(200);
});

app.post('/api/users/unblock', async (req, res) => {
  const { ids } = req.body;
  await pool.query("UPDATE users SET status = 'active' WHERE id = ANY($1)", [ids]);
  res.sendStatus(200);
});

app.post('/api/users/delete', async (req, res) => {
  const { ids } = req.body;
  await pool.query("DELETE FROM users WHERE id = ANY($1)", [ids]);
  res.sendStatus(200);
});

app.post('/api/users/delete-unverified', async (req, res) => {
  await pool.query("DELETE FROM users WHERE status = 'unverified'");
  res.sendStatus(200);
});

const PORT = process.env.PORT || 5000;

if (!PORT) {
  console.error('PORT is not defined');
  process.exit(1);
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is listening on port ${PORT}`);
});
