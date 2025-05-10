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
const pool             = require('./db');
const signupRouter     = require('./routes/signup');

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
  secret:            process.env.SESSION_SECRET,
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

// ─── Mount profile‐completion routes ────────────────────────────────────────
app.use(signupRouter);

// ─── Simple test route ──────────────────────────────────────────────────────
app.get('/hello', (_, res) => res.send('Hello world'));

// ─── Auth helper for explicit routes ────────────────────────────────────────
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
      // pull the e-mail out…
      const email = profile.emails[0];
      // …and attach it to the profile object
      profile.Email = email;

      // derive a display name
      const name = profile.displayName || email.split('@')[0];

      // upsert shell user
      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [name, email]
      );

      // fetch id & perms
      const [[u]]  = await pool.execute(
        `SELECT UserID FROM users WHERE Email = ?`,
        [email]
      );
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
      `SELECT UserID, Username, Email FROM users WHERE UserID = ?`,
      [id]
    );
    done(null, row || false);
  } catch (e) {
    done(e);
  }
});

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// home
app.get('/', (req, res) => res.render('home', { user: req.user }));

// login
app.get(
  '/login',
  (req, res, next) => {
    console.log('→ [login] redirectUri =', redirectUri);
    next();
  },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// debug + callback
app.get(
  callbackPath,
  (req, res, next) => {
    console.log('*** CALLBACK HIT ***', req.method, req.originalUrl, req.query);
    next();
  },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  async (req, res, next) => {
    try {
      // load profile_complete
      const [[row]] = await pool.execute(
        `SELECT profile_complete FROM users WHERE UserID = ?`,
        [req.user.UserID]
      );
      const isComplete = !!row.profile_complete;
      req.user.profileComplete = isComplete;

      console.log(`*** PASSED AUTH, onboarding check: ${req.user.Email} profile_complete=${row.profile_complete}`);

      // redirect
      return isComplete
        ? res.redirect('/dashboard')
        : res.redirect('/complete-profile');
    } catch (err) {
      next(err);
    }
  }
);

// helper to protect pages
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// dashboard
app.get('/dashboard', ensureLoggedIn, (req, res) => {
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
