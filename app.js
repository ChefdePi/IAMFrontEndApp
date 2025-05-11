// ─── app.js ─────────────────────────────────────────────────────────
require('dotenv').config();
const express          = require('express');
const session          = require('express-session');
const passport         = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const morgan           = require('morgan');
const path             = require('path');

const pool              = require('./db');
const signupRouter      = require('./routes/signup');
const permissionsRouter = require('./routes/permissions');
const rolesRouter       = require('./routes/roles');
const usersRouter       = require('./routes/users');
const { requirePermission } = require('./rbac');

const PORT = process.env.PORT || 3000;
const app  = express();

// Build host & redirectUri
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http') ? rawHost : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/') ? process.env.CALLBACK_PATH : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// Logging, Body-parsing, Static
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// EJS
app.set('view engine', 'ejs');
app.set('views',       path.join(__dirname, 'views'));

// Session & Passport
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

// Helpers
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// Azure B2C OIDC Strategy
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
      // 1) Extract email
      let email =
           profile?.emails?.[0]
        || profile?._json?.emails?.[0]
        || profile?._json?.email
        || profile?.upn
        || null;
      if (!email) {
        console.warn('⚠️ No email claim – falling back to sub:', profile.sub);
        email = `${profile.sub}@no-email.local`;
      }
      profile.Email = email;

      // 2) Grab the B2C object-ID (mandatory)
      const objectId = profile.oid || profile.sub;

      // 3) Upsert user, including AzureB2CObjectId
      await pool.execute(
        `INSERT INTO Users (AzureB2CObjectId, Email, DisplayName)
             VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
             DisplayName      = VALUES(DisplayName),
             AzureB2CObjectId = VALUES(AzureB2CObjectId)`,
        [objectId, email, profile.displayName || email.split('@')[0]]
      );

      // 4) Fetch full user record
      const [[u]] = await pool.execute(
        `SELECT UserID, first_name, last_name, role, profile_complete
           FROM Users
          WHERE AzureB2CObjectId = ?`,
        [objectId]
      );
      profile.UserID           = u.UserID;
      profile.first_name       = u.first_name;
      profile.last_name        = u.last_name;
      profile.role             = u.role;
      profile.profile_complete = u.profile_complete === 1;
      profile.profileComplete  = profile.profile_complete;

      // 5) Load permissions if profile is complete
      if (profile.profileComplete) {
        const [rows] = await pool.execute(`
          SELECT p.PermissionName
            FROM Permissions p
            JOIN RolePermissions rp ON rp.PermissionID = p.PermissionID
            JOIN UserRoles ur       ON ur.RoleID       = rp.RoleID
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
passport.serializeUser((u, done) => done(null, u));
passport.deserializeUser((u, done) => done(null, u));

// Public & Signup routes
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
app.get('/',            (req, res) => res.render('home',      { user: req.user }));
app.get('/dashboard',   ensureLoggedIn,        (req, res) => res.render('dashboard', { user: req.user }));
app.get('/profile',     ensureLoggedIn,        (req, res) => res.render('profile',   { user: req.user }));

// Mount & protect RBAC routes
app.use(
  '/permissions',
  requirePermission('ManageUsers'),
  permissionsRouter
);
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

// Start server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
