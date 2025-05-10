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

// ─── Build redirectUri & host ────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http')
                     ? rawHost
                     : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Express / EJS / Static ──────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views',    path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ─── Secure Session Cookies ──────────────────────────────────────────
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

// ─── Mount signup‐completion routes ─────────────────────────────────
app.use('/', signupRouter);

// ─── Helpers ─────────────────────────────────────────────────────────
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }
    if (req.user.role === role) {
      return next();
    }
    res.status(403).render('forbidden', { user: req.user });
  };
}

// ─── Azure B2C OIDC Strategy ────────────────────────────────────────
const tenant = process.env.AZURE_AD_B2C_TENANT;
const policy = process.env.AZURE_AD_B2C_POLICY;  // must match e.g. "B2C_1_signin_signup"

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
      // Extract email
      let email =
           profile?.emails?.[0]
        || profile?._json?.emails?.[0]
        || profile?._json?.email
        || profile?.upn
        || null;
      if (!email) {
        console.warn('⚠️ No email claim; falling back to sub:', profile.sub);
        email = `${profile.sub}@no-email.local`;
      }
      profile.Email    = email;
      profile.Username = profile.displayName || email.split('@')[0];

      // Upsert shell user
      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [profile.Username, email]
      );

      // Fetch completion flag
      const [[u]] = await pool.execute(
        `SELECT UserID, profile_complete FROM users WHERE Email = ?`,
        [email]
      );
      profile.UserID           = u.UserID;
      profile.profile_complete = u.profile_complete === 1;
      profile.profileComplete  = u.profile_complete === 1;  // camelCase for EJS

      // Load perms if complete
      if (profile.profileComplete) {
        const [rows] = await pool.execute(`
          SELECT p.PermissionName
            FROM permissions p
            JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
            JOIN userroles ur       ON ur.RoleID       = rp.RoleID
           WHERE ur.UserID = ?`,
          [u.UserID]
        );
        profile.perms = rows.map(r => r.PermissionName);
      } else {
        profile.perms = [];
      }

      done(null, profile);
    } catch (err) {
      done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── ROUTES ──────────────────────────────────────────────────────────
app.get('/',        (req, res) => res.render('home',      { user: req.user }));
app.get('/login',   passport.authenticate('azuread-openidconnect',{ failureRedirect: '/' }));
app.get(callbackPath,
  passport.authenticate('azuread-openidconnect',{ failureRedirect: '/' }),
  (req, res) => {
    if (!req.user.profileComplete) {
      return res.redirect('/complete-profile');
    }
    res.redirect('/dashboard');
  }
);
app.get('/dashboard', ensureLoggedIn, (req, res) => res.render('dashboard',{ user: req.user }));
app.get('/protected', ensureLoggedIn, (req, res) => res.render('protected',{ user: req.user }));
app.get('/profile',   ensureLoggedIn, (req, res) => res.render('profile',  { user: req.user }));

// Admin UI
app.get('/admin/users', requireRole('admin'), async (req, res, next) => {
  try {
    const [users] = await pool.execute(`
      SELECT UserID, Email, first_name, last_name, role, profile_complete
        FROM users
       WHERE profile_complete = 0
    `);
    res.render('admin-users', { user: req.user, pending: users });
  } catch (err) {
    next(err);
  }
});
app.post('/admin/users/approve', requireRole('admin'),
  express.urlencoded({ extended: false }), async (req, res, next) => {
    try {
      await pool.execute(
        `UPDATE users SET profile_complete = 1 WHERE UserID = ?`,
        [req.body.id]
      );
      res.redirect('/admin/users');
    } catch (err) {
      next(err);
    }
});

// Logout
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

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
