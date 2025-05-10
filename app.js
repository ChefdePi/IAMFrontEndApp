require('dotenv').config();
const express          = require('express');
const session          = require('express-session');
const passport         = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const morgan           = require('morgan');
const path             = require('path');
const pool             = require('./db');
const signupRouter     = require('./routes/signup');

const PORT = process.env.PORT || 3000;
const app  = express();

// ─── Build redirectUri ────────────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http') ? rawHost : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Express / EJS / Static ──────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ─── Secure Session Cookies ──────────────────────────────────────────
app.set('trust proxy', 1);
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret-9876',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   true,    // Azure requires HTTPS
    sameSite: 'Lax',
    maxAge:   1000 * 60 * 30  // 30 minutes
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ─── Mount the signup‐completion routes ──────────────────────────────
app.use('/', signupRouter);

// ─── Azure B2C OIDC Strategy ────────────────────────────────────────
passport.use('azuread-openidconnect', new OIDCStrategy({
    identityMetadata:  `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
                       `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
                       `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:          process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:      process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:       redirectUri,
    responseType:      'code',
    responseMode:      'query',
    scope:             ['openid','profile','email','offline_access'],
    allowHttpForRedirectUrl: host.startsWith('http://'),
    validateIssuer:    false
  },
  async (_iss, _sub, profile, _accessToken, _refreshToken, done) => {
    try {
      // 1) Extract email from whatever claim it lives in
      let email =
           profile?.emails?.[0]
        || profile?._json?.emails?.[0]
        || profile?._json?.email
        || profile?.upn
        || null;

      if (!email) {
        console.warn('⚠️ No email in token; falling back to sub:', profile.sub);
        email = `${profile.sub}@no-email.local`;
      }
      profile.Email = email;

      const name = profile.displayName || email.split('@')[0];

      // 2) Ensure there’s a “shell” row in users
      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [name, email]
      );

      // 3) Check whether they’ve completed their profile
      const [[u]] = await pool.execute(
        `SELECT UserID, profile_complete 
           FROM users 
          WHERE Email = ?`,
        [email]
      );
      profile.UserID           = u.UserID;
      profile.profile_complete = u.profile_complete === 1;
      profile.Username         = name;

      // 4) If they *have* completed, load their permissions
      if (profile.profile_complete) {
        const [rows] = await pool.execute(`
          SELECT p.PermissionName
            FROM permissions p
            JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
            JOIN userroles ur       ON ur.RoleID       = rp.RoleID
           WHERE ur.UserID = ?
        `, [u.UserID]);
        profile.perms = rows.map(r => r.PermissionName);
      } else {
        profile.perms = [];
      }

      console.log('→ Auth OK:', {
        email:    profile.Email,
        userId:   profile.UserID,
        complete: profile.profile_complete
      });
      done(null, profile);

    } catch (err) {
      console.error('🔴 Auth callback error', err);
      done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── ROUTES ──────────────────────────────────────────────────────────
// Home
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

// Kick off B2C login
app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// Callback from B2C
app.get(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    // If they haven’t filled out profile yet, send them there…
    if (!req.user.profile_complete) {
      return res.redirect('/complete-profile');
    }
    // Otherwise let them into the protected area
    res.redirect('/protected');
  }
);

// Protected page
app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>Welcome, ${req.user.Username}</h1>
    <p>Email: ${req.user.Email}</p>
    <p>Permissions: ${req.user.perms.join(', ') || '(none)'}</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get('/logout', (req, res, next) =>
  req.logout(err => err ? next(err) : res.redirect('/'))
);

// Start server
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
