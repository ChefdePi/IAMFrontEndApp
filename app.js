// ─── Load ENV & Debug ───────────────────────────────────────────────────────
require('dotenv').config();
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

const app = express();
const PORT = 3000;

// ─── MySQL POOL ──────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.MYSQL_HOST,
  user:     process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: true } // if you’re using the Baltimore cert
});

// ─── Middleware & Static ──────────────────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ─── Test Route ──────────────────────────────────────────────────────────────
app.get('/hello', (req, res) => res.send('👋 Hello world'));

// ─── Authorization Helper ─────────────────────────────────────────────────────
// Usage: app.get('/admin', needPerm('ManageUsers'), (req,res)=>…)
function needPerm(permName) {
  return (req, res, next) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.redirect('/login');
    }
    if (req.user.perms?.includes(permName)) {
      return next();
    }
    return res.status(403).send(`Forbidden – you need the "${permName}" permission`);
  };
}

// ─── OIDC STRATEGY w/ DB UPSERT & PERMS LOAD ─────────────────────────────────
const azureStrategy = new OIDCStrategy(
  {
    identityMetadata:
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID: process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret: process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl: `${process.env.PUBLIC_HOST}${process.env.CALLBACK_PATH}`,
    allowHttpForRedirectUrl: process.env.PUBLIC_HOST.startsWith('http://'),
    responseType: 'code',
    responseMode: 'query',
    scope: ['openid', 'profile', 'offline_access'],
    validateIssuer: false
  },
  async (iss, sub, profile, accessToken, refreshToken, done) => {
    try {
      // ── 1) UPSERT the user into your users table ───────────────────────────
      //  • Change `users` & column names below to match your schema
      const email = profile.emails[0];
      const name  = profile.displayName || email.split('@')[0];

      await pool.execute(
        `INSERT INTO users (Username, Email)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE
           Username = VALUES(Username)`,
        [name, email]
      );

      // fetch back their PK (UserID)
      const [[userRow]] = await pool.execute(
        `SELECT UserID, Username, Email
           FROM users
          WHERE Email = ?`,
        [email]
      );
      if (!userRow) {
        return done(new Error('User not found after upsert'));
      }
      profile.dbId = userRow.UserID;

      // ── 2) LOAD their permissions via roles/rolepermissions ───────────────
      //  • Change `permissions`, `rolepermissions`, `userroles` table names
      const [perms] = await pool.execute(
        `SELECT p.PermissionName
           FROM permissions p
           JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
           JOIN userroles ur       ON ur.RoleID       = rp.RoleID
          WHERE ur.UserID = ?`,
        [profile.dbId]
      );
      profile.perms = perms.map(r => r.PermissionName);

      console.log(`  User ${email} (id=${profile.dbId}) has perms:`, profile.perms);
      return done(null, profile);
    } catch (err) {
      console.error('  Auth callback error:', err);
      return done(err);
    }
  }
);
azureStrategy.name = 'azuread-openidconnect';
passport.use(azureStrategy);

// ─── Serialize / Deserialize ─────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.dbId));
passport.deserializeUser(async (id, done) => {
  try {
    // grab minimal row + perms from session store or DB if you like
    const [[row]] = await pool.execute(
      `SELECT UserID, Username, Email
         FROM users
        WHERE UserID = ?`,
      [id]
    );
    // we already did perms in the callback, so row.perms must come from session
    done(null, row || false);
  } catch (err) {
    done(err);
  }
});

// ─── Routes ──────────────────────────────────────────────────────────────────
app.get('/',              (req, res) => res.render('home', { user: req.user }));
app.get('/login',         passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }));
app.get(
  process.env.CALLBACK_PATH,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => res.redirect('/protected')
);

// unprotected profile
app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>👋 Welcome, ${req.user.Username}</h1>
    <p>Your permissions: ${req.user.perms.join(', ')}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

// example protected route
app.get('/dashboard',
  needPerm('ViewDashboard'),
  (req, res) => res.send('<h2> Dashboard Data…</h2>')
);

// example POST-only route
app.post('/tasks/update',
  needPerm('UpdateCareTasks'),
  (req, res) => {
    // …update a task…
    res.json({ success: true });
  }
);

app.get('/logout', (req, res, next) => {
  req.logout(err => err ? next(err) : res.redirect('/'));
});

// ─── START SERVER ───────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
