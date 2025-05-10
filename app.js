// app.js
require('dotenv').config();

// ─── ENV DEBUG ──────────────────────────────────────────────────────────────
console.log(
  `Loaded ENV: Tenant=${process.env.AZURE_AD_B2C_TENANT}` +
  ` Policy=${process.env.AZURE_AD_B2C_POLICY}` +
  ` ClientID=${process.env.AZURE_AD_B2C_CLIENT_ID}` +
  ` Callback=${process.env.CALLBACK_PATH}`
);

const express          = require('express');
const session          = require('express-session');
const passport         = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const morgan           = require('morgan');
const path             = require('path');
const mysql            = require('mysql2/promise');

// ← centralized pool
const pool         = require('./db');
// ← profile‐completion routes
const signupRouter = require('./routes/signup');

const PORT = process.env.PORT || 3000;
const app  = express();

// ─── Build redirectUri ──────────────────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http')
                     ? rawHost
                     : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Express / EJS / Static ─────────────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ─── Secure Session Cookies ─────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(session({
  secret:            process.env.SESSION_SECRET,    // ← must be in Azure App Settings
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ─── Mount signup routes ────────────────────────────────────────────────────
app.use(signupRouter);

// ─── Test route ─────────────────────────────────────────────────────────────
app.get('/hello', (_, res) => res.send('Hello world'));

// ─── RBAC helper ─────────────────────────────────────────────────────────────
function needPerm(name) {
  return (req, res, next) => {
    if (!req.isAuthenticated?.() || !req.user?.perms?.includes(name)) {
      return res.status(403).send(`Forbidden – missing "${name}"`);
    }
    next();
  };
}

// ─── Azure B2C OIDC Strategy ─────────────────────────────────────────────────
passport.use('azuread-openidconnect', new OIDCStrategy(
  {
    identityMetadata:
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:                process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:            process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:             redirectUri,
    allowHttpForRedirectUrl: host.startsWith('http://'),
    responseType:            'code',
    responseMode:            'query',
    scope:                   ['openid','profile','offline_access'],
    validateIssuer:          false
  },
  async (_iss, _sub, profile, _accessToken, _refreshToken, done) => {
    try {
      // upsert shell user
      const email = profile.emails[0];
      const name  = profile.displayName || email.split('@')[0];
      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [name, email]
      );

      // fetch id & perms
      const [[u]]  = await pool.execute(`SELECT UserID FROM users WHERE Email = ?`, [email]);
      const [rows] = await pool.execute(`
        SELECT p.PermissionName
          FROM permissions p
          JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
          JOIN userroles ur       ON ur.RoleID       = rp.RoleID
         WHERE ur.UserID = ?
      `, [u.UserID]);

      profile.dbId     = u.UserID;
      profile.UserID   = u.UserID;
      profile.Username = name;
      profile.perms    = rows.map(r => r.PermissionName);

      console.log(`→ user ${email} (id=${u.UserID}) perms:`, profile.perms);
      done(null, profile);
    } catch (err) {
      console.error('Auth callback error:', err);
      done(err);
    }
  }
));

// ─── Sessions ────────────────────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.dbId));
passport.deserializeUser(async (id, done) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT UserID, Username, Email FROM users WHERE UserID = ?`, [id]
    );
    done(null, row || false);
  } catch (e) {
    done(e);
  }
});

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// home
app.get('/', (req, res) => res.render('home', { user: req.user }));

// kick off login
app.get('/login',
  (req, _res, next) => { console.log('→ [login] redirectUri =', redirectUri); next(); },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// **LOG & PROCEED** callback
app.get(callbackPath,
  (req, _res, next) => { console.log('→ [callback] query =', req.query); next(); },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  async (req, res) => {
    console.log('🔥 Entered post‐auth handler for userID=', req.user.UserID);

    // load flag
    const [[row]] = await pool.execute(
      'SELECT profile_complete FROM users WHERE UserID = ?', [req.user.UserID]
    );
    console.log('🔥 profile_complete flag =', row.profile_complete);

    req.user.profileComplete = !!row.profile_complete;
    res.redirect('/dashboard');
  }
);

// dashboard
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.render('dashboard', { user: req.user });
});

// protected example
app.get('/protected', needPerm('ViewDashboard'), (req, res) => {
  res.send(`
    <h1>Welcome, ${req.user.Username}</h1>
    <p>Perms: ${req.user.perms.join(', ') || '(none)'}</p>
    <a href="/logout">Logout</a>
  `);
});

// logout
app.get('/logout', (req, res, next) =>
  req.logout(err => err ? next(err) : res.redirect('/'))
);

// start
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
