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

app.use(passport.initialize());
app.use(passport.session());

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
    res.send(`Hello, ${req.user.name}! You signed up with Google.`);
  }
);

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields must be filled' });
    }

    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        const user = await registerUser(name, email, passwordHash);

        res.status(201).json({ message: 'User is registered', user });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ message: 'Email is already in use' });
        }
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

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

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is listening on http://localhost:${PORT}`);
});