const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('./db');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { registerUser } = require('./auth');
const path = require('path');

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

// important: this middleware is the only place for security checks
const checkUserStatus = async (req, res, next) => {
  if (req.path === '/api/register' || req.path === '/auth/google' || req.path === '/auth/google/callback' || req.path === '/' || req.path === '/api/subscribe' || req.path === '/api/login') {
    return next();
  }

  if (!req.user) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    // note: query status directly from database to ensure real-time check
    const result = await pool.query('SELECT status FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user || user.status === 'blocked') {
      req.logout(() => { });
      return res.status(401).json({ message: "User is blocked or deleted" });
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

      await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

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
    const newUser = await registerUser(name, email, password);

    req.login(newUser, async (err) => {
      if (err) {
        console.error("Login after register error:", err);
        return res.status(500).json({ message: "Registered, but login failed" });
      }
      
      await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [newUser.id]);

      return res.status(201).json({
        message: "User registered and logged in",
        user: { id: newUser.id, name: newUser.name, email: newUser.email }
      });
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: "Email already exists" });
    }
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!user.password_hash) {
      return res.status(400).json({ message: "This account is registered via Google. Please log in with Google." });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    req.login(user, async (err) => {
      if (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Error establishing session" });
      }
      
      await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

      return res.json({ 
        message: "Logged in successfully", 
        user: { id: user.id, name: user.name, email: user.email } 
      });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, status, last_login AS "lastLogin" FROM users ORDER BY last_login DESC');
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
  const { ids } = req.body;
  await pool.query("DELETE FROM users WHERE status = 'unverified' AND id = ANY($1)", [ids]);
  res.sendStatus(200);
});

const PORT = process.env.PORT || 5000;

if (!PORT) {
  console.error('PORT is not defined');
  process.exit(1);
}

app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'bike.html'));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server is listening on port ${PORT}`);
});