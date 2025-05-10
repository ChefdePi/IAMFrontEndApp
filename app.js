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

// ─── Helper to guard routes ───────────────────────────────────────────
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// ─── Azure B2C OIDC Strategy ────────────────────────────────────────
const tenant = process.env.AZURE_AD_B2C_TENANT;
const policy = process.env.AZURE_AD_B2C_POLICY;  // e.g. "B2C_1_signin_signup"

passport.use('azuread-openidconnect', new OIDCStrategy({
    // Policy‐specific metadata (absolute URLs)
    identityMetadata:
      `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/` +
      `${policy}/v2.0/.well-known/openid-configuration` +
      `?p=${policy}`,
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
      // 1) Extract or synthesize an email
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
      profile.Email = email;
      profile.Username = profile.displayName || email.split('@')[0];

      // 2) Upsert a “shell” user record
      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [profile.Username, email]
      );

      // 3) Fetch completion flag
      const [[u]] = await pool.execute(
        `SELECT UserID, profile_complete
           FROM users
          WHERE Email = ?`,
        [email]
      );
      profile.UserID           = u.UserID;
      profile.profile_complete = u.profile_complete === 1;
      profile.profileComplete  = u.profile_complete === 1;  // camelCase for your EJS

      // 4) Load permissions if they’ve completed
      if (profile.profileComplete) {
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
        complete: profile.profileComplete
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

// Public Home
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

// Kick off login
app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// Callback from B2C
app.get(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    if (!req.user.profileComplete) {
      return res.redirect('/complete-profile');
    }
    res.redirect('/dashboard');
  }
);

// Dashboard (protected)
app.get('/dashboard', ensureLoggedIn, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// Protected demo
app.get('/protected', ensureLoggedIn, (req, res) => {
  res.render('protected', { user: req.user });
});

// Logout – clear session + redirect to B2C sign-out
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('connect.sid', { path: '/' });

      const postLogout = encodeURIComponent(host);
      const signOutUrl =
        `https://${tenant}.b2clogin.com/` +
        `${tenant}.onmicrosoft.com/${policy}/oauth2/v2.0/logout` +
        `?p=${policy}` +
        `&post_logout_redirect_uri=${postLogout}`;

      res.redirect(signOutUrl);
    });
  });
});

// Start server
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
