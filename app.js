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

const PORT = process.env.PORT || 3000;
const app  = express();

// ─── Redirect URI ───────────────────────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http') ? rawHost : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
  ? process.env.CALLBACK_PATH
  : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;

console.log('→ Using redirectUri:', redirectUri);

// ─── MySQL Pool ─────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:               process.env.AZURE_MYSQL_HOST,
  user:               process.env.AZURE_MYSQL_USERNAME,
  password:           process.env.AZURE_MYSQL_PASSWORD,
  database:           process.env.AZURE_MYSQL_DBNAME,
  port:               parseInt(process.env.AZURE_MYSQL_PORT, 10) || 3306,
  waitForConnections: true,
  connectionLimit:    10,
  ssl:                { rejectUnauthorized: true }
});

// ─── Middleware / Views ─────────────────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret:            'your-session-secret',
  resave:            false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// ─── Simple Test Route ──────────────────────────────────────────────────────
app.get('/hello', (_, res) => res.send('Hello world'));

// ─── Auth Helper ────────────────────────────────────────────────────────────
function needPerm(name) {
  return (req, res, next) => {
    if (!req.isAuthenticated?.() || !req.user?.perms?.includes(name)) {
      return res.status(403).send(`Forbidden – missing "${name}"`);
    }
    next();
  };
}

// ─── OIDC STRATEGY ──────────────────────────────────────────────────────────
const azureStrategy = new OIDCStrategy(
  {
    identityMetadata:
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    issuer:            'https://eld3rsecb2c.b2clogin.com/6f61f7c7-e051-4385-bae7-793d6e46047b/v2.0/',
    clientID:          process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:      process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:       redirectUri,
    allowHttpForRedirectUrl: host.startsWith('http://'),
    responseType:      'code',
    responseMode:      'query',
    scope:             ['openid', 'profile', 'offline_access'],
    validateIssuer:    true
  },
  async (_iss, _sub, profile, _at, _rt, done) => {
    try {
      const email = profile.emails[0];
      const name  = profile.displayName || email.split('@')[0];

      // upsert user
      await pool.execute(
        `INSERT INTO users (Username, Email)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [name, email]
      );

      // fetch UserID
      const [[u]] = await pool.execute(
        `SELECT UserID FROM users WHERE Email = ?`, [email]
      );
      if (!u) return done(new Error('User row missing after upsert'));

      // perms
      const [rows] = await pool.execute(
        `SELECT p.PermissionName
           FROM permissions p
           JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
           JOIN userroles ur       ON ur.RoleID       = rp.RoleID
          WHERE ur.UserID = ?`, [u.UserID]
      );
      profile.dbId  = u.UserID;
      profile.perms = rows.map(r => r.PermissionName);

      console.log(`→ user ${email} (id=${u.UserID}) perms:`, profile.perms);
      done(null, profile);
    } catch (err) {
      done(err);
    }
  }
);
passport.use('azuread-openidconnect', azureStrategy);
passport.serializeUser((u, d) => d(null, u.dbId));
passport.deserializeUser(async (id, d) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT UserID, Username, Email FROM users WHERE UserID = ?`, [id]
    );
    d(null, row || false);
  } catch (err) { d(err); }
});

// ─── ROUTES ─────────────────────────────────────────────────────────────────

// HOME page (renders /views/home.ejs)
app.get('/', (req, res) => res.render('home', { user: req.user }));

// LOGIN
app.get('/login',
  (req, _res, next) => { console.log('→ [login] redirectUri =', redirectUri); next(); },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// CALLBACK
app.get(callbackPath,
  (req, _res, next) => { console.log('→ [callback] query =', req.query); next(); },
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => res.redirect('/protected')
);

// PROTECTED
app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>Welcome, ${req.user.Username}</h1>
    <p>Perms: ${req.user.perms.join(', ') || '(none)'}</p>
    <a href="/logout">Logout</a>
  `);
});

// SAMPLE EXTRA ROUTES
app.get('/dashboard',    needPerm('ViewDashboard'),   (_, res) => res.send('<h2>Dashboard…</h2>'));
app.post('/tasks/update', needPerm('UpdateCareTasks'), (_, res) => res.json({ ok: true }));

// LOGOUT
app.get('/logout', (req, res, next) =>
  req.logout(err => err ? next(err) : res.redirect('/'))
);

// ─── START ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
