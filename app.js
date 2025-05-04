// app.js
require('dotenv').config();

// Log basic ENV load
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

// Pick up Azure's port or default to 3000
const PORT = process.env.PORT || 3000;
const app  = express();

// ─── Compute a single redirectUri ────────────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || ''
const host         = rawHost.startsWith('http') 
                         ? rawHost 
                         : `https://${rawHost}`
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                         ? process.env.CALLBACK_PATH
                         : `/${process.env.CALLBACK_PATH}`
const redirectUri  = `${host}${callbackPath}`

console.log('→ Using redirectUri:', redirectUri)

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

// ─── Middleware & Views ─────────────────────────────────────────────────────
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
app.get('/hello', (req, res) => {
  res.send('Hello world');
});

// ─── Authorization Middleware ────────────────────────────────────────────────
function needPerm(permName) {
  return (req, res, next) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.redirect('/login');
    }
    if (req.user.perms && req.user.perms.includes(permName)) {
      return next();
    }
    return res.status(403).send(`Forbidden – you need the "${permName}" permission`);
  };
}

// ─── Azure AD B2C Strategy ──────────────────────────────────────────────────
const azureStrategy = new OIDCStrategy(
  {
    identityMetadata:          `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
                               `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
                               `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:                  process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:              process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:               redirectUri,
    allowHttpForRedirectUrl:   process.env.PUBLIC_HOST.startsWith('http://'),
    responseType:              'code',
    responseMode:              'query',
    scope:                     ['openid','profile','offline_access'],
    validateIssuer:            false
  },
  async (iss, sub, profile, accessToken, refreshToken, done) => {
    try {
      // 1) Upsert the user
      const email = profile.emails[0];
      const name  = profile.displayName || email.split('@')[0];

      await pool.execute(
        `INSERT INTO users (Username, Email)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE
             Username = VALUES(Username)`,
        [name, email]
      );

      // 2) Fetch their UserID
      const [[userRow]] = await pool.execute(
        `SELECT UserID FROM users WHERE Email = ?`,
        [email]
      );
      if (!userRow) {
        return done(new Error('User not found after upsert'));
      }
      profile.dbId = userRow.UserID;

      // 3) Load their permissions
      const [rows] = await pool.execute(
        `SELECT p.PermissionName
           FROM permissions p
           JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
           JOIN userroles ur       ON ur.RoleID       = rp.RoleID
          WHERE ur.UserID = ?`,
        [profile.dbId]
      );
      profile.perms = rows.map(r => r.PermissionName);

      console.log(`User ${email} (id=${profile.dbId}) has perms:`, profile.perms);
      done(null, profile);

    } catch (err) {
      console.error('Auth callback error:', err);
      done(err);
    }
  }
);

azureStrategy.name = 'azuread-openidconnect';
passport.use(azureStrategy);

// ─── Session Serialization ─────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.dbId));
passport.deserializeUser(async (id, done) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT UserID, Username, Email FROM users WHERE UserID = ?`,
      [id]
    );
    done(null, row || false);
  } catch (err) {
    done(err);
  }
});

// ─── Routes ─────────────────────────────────────────────────────────────────
app.get('/',       (req, res) => res.render('home', { user: req.user }));
app.get('/login',  passport.authenticate('azuread-openidconnect', { failureRedirect:'/' }));
app.get(
  process.env.CALLBACK_PATH,
  passport.authenticate('azuread-openidconnect', { failureRedirect:'/' }),
  (req, res) => res.redirect('/protected')
);

app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>Welcome, ${req.user.Username}</h1>
    <p>Your permissions: ${req.user.perms.join(', ')}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

app.get('/dashboard',       needPerm('ViewDashboard'),   (req, res) => res.send('<h2>Dashboard Data…</h2>'));
app.post('/tasks/update',   needPerm('UpdateCareTasks'), (req, res) => res.json({ success: true }));

app.get('/logout', (req, res, next) => {
  req.logout(err => err ? next(err) : res.redirect('/'));
});

// ─── Start Server ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
