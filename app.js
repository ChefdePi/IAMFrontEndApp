require('dotenv').config();
const express          = require('express');
const session          = require('express-session');
const passport         = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const morgan           = require('morgan');
const path             = require('path');

const pool             = require('./db');
const signupRouter     = require('./routes/signup');
const rolesRouter      = require('./routes/roles');
const usersRouter      = require('./routes/users');
const { requirePermission } = require('./rbac');

const PORT = process.env.PORT || 3000;
const app  = express();

// ─── Build host & redirectUri ────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http')
                     ? rawHost
                     : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Middleware: Logging, Body-parsing, Static files ─────────────────
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── View engine ────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views',       path.join(__dirname, 'views'));

// ─── Session & Passport setup ───────────────────────────────────────
app.set('trust proxy', 1);
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   true,
    sameSite: 'Lax',
    maxAge:   1000 * 60 * 30
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// ─── Helpers ─────────────────────────────────────────────────────────
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (req.user.role === role) return next();
    res.status(403).render('forbidden', { user: req.user });
  };
}

// ─── Azure B2C OIDC Strategy ────────────────────────────────────────
const tenant = process.env.AZURE_AD_B2C_TENANT;
const policy = process.env.AZURE_AD_B2C_POLICY;
passport.use('azuread-openidconnect', new OIDCStrategy({
    identityMetadata:
      `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/` +
      `${policy}/v2.0/.well-known/openid-configuration?p=${policy}`,
    clientID:               process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:           process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:            redirectUri,
    responseType:           'code',
    responseMode:           'query',
    scope:                  ['openid','profile','email','offline_access'],
    allowHttpForRedirectUrl: host.startsWith('http://'),
    validateIssuer:         false
  },
  async (_iss, _sub, profile, _accessToken, _refreshToken, done) => {
    try {
      // … your upsert + load perms logic as before …
      done(null, profile);
    } catch (err) {
      done(err);
    }
  }
));
passport.serializeUser((u, done) => done(null, u));
passport.deserializeUser((u, done) => done(null, u));

// ─── Public & Signup‐completion Routes ──────────────────────────────
app.use('/', signupRouter);

app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

app.get(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    if (!req.user.profileComplete) {
      return res.redirect('/complete-profile');
    }
    res.redirect('/dashboard');
  }
);

app.get('/',       (req, res) => res.render('home',      { user: req.user }));
app.get('/dashboard', ensureLoggedIn, (req, res) => res.render('dashboard', { user: req.user }));
app.get('/profile',   ensureLoggedIn, (req, res) => res.render('profile',   { user: req.user }));

// ─── Mount & Protect RBAC Admin Routes ──────────────────────────────
app.use(
  '/roles',
  requirePermission('ManageUsers'),
  rolesRouter
);
app.use(
  '/users',
  requirePermission('ManageUsers'),
  usersRouter
);

// ─── Other Role‐ or Session‐based Routes ─────────────────────────────
app.get('/reports', ensureLoggedIn, (req, res) => {
  if (!req.user.perms.includes('ViewDashboard')) {
    return res.status(403).render('forbidden', { user: req.user });
  }
  res.render('reports', { user: req.user });
});

// ─── Admin UI (using requireRole as an alternative) ──────────────────
app.get('/admin/users',
  requireRole('admin'),
  async (req, res, next) => {
    try {
      const [users] = await pool.execute(
        `SELECT UserID, Email, profile_complete FROM users WHERE profile_complete = 0`
      );
      res.render('admin-users', { user: req.user, pending: users });
    } catch (err) {
      next(err);
    }
  }
);

// ─── Logout ──────────────────────────────────────────────────────────
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('connect.sid', { path: '/' });
      const post = encodeURIComponent(host);
      const signOutUrl =
        `https://${tenant}.b2clogin.com/` +
        `${tenant}.onmicrosoft.com/${policy}/oauth2/v2.0/logout` +
        `?p=${policy}&post_logout_redirect_uri=${post}`;
      res.redirect(signOutUrl);
    });
  });
});

// ─── Start Server ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
const permissionsRouter = require('./routes/permissions');

app.use(
  '/permissions',
  requirePermission('ManageUsers'),
  permissionsRouter
);