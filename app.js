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

// ─── Build redirectUri ────────────────────────────────
const rawHost      = process.env.PUBLIC_HOST || '';
const host         = rawHost.startsWith('http') ? rawHost : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Express / EJS / Static ───────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// ─── Secure Session Cookies ────────────────────────────
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-9876',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // Azure requires HTTPS
    sameSite: 'Lax',     // CSRF protection
    maxAge: 1000 * 60 * 30  // 30 minutes
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ─── Mount profile‐completion routes ─────────────────
app.use(signupRouter);

// ─── Azure B2C OIDC Strategy ─────────────────────────
passport.use(new OIDCStrategy({
    identityMetadata:
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:                process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:            process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:             redirectUri,
    responseType:            'code',
    responseMode:            'query',
    scope: ['openid','profile','email','offline_access'],
    allowHttpForRedirectUrl: host.startsWith('http://'),
    validateIssuer:          false
  },
async (_iss, _sub, profile, _accessToken, _refreshToken, done) => {
  try {
    // 1) Robustly pull an email out of whatever claim the token actually returned:
    const email =
         profile?.emails?.[0]           // normal local account
      || profile?._json?.emails?.[0]    // some social IdPs stick it under _json.emails
      || profile?.upn                  // fallback to UPN (often in `preferred_username`)
      || null;

    if (!email) {
      console.error('❌ No email in ID-token, raw profile:', JSON.stringify(profile, null,2));
      // gracefully reject rather than blow up
      return done(null, false, { message: 'Email claim missing' });
    }

    profile.Email = email;
    const name    = profile.displayName || email.split('@')[0];

    // 2) Your existing upsert logic...
    await pool.execute(
      `INSERT INTO users (Username, Email)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
      [name, email]
    );

    const [[u]] = await pool.execute(
      `SELECT UserID FROM users WHERE Email = ?`, 
      [email]
    );
    const [rows] = await pool.execute(`
      SELECT p.PermissionName
        FROM permissions p
        JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
        JOIN userroles ur       ON ur.RoleID       = rp.RoleID
       WHERE ur.UserID = ?`,
      [u.UserID]
    );

    profile.dbId     = u.UserID;
    profile.UserID   = u.UserID;
    profile.Username = name;
    profile.perms    = rows.map(r => r.PermissionName);

    console.log('→ Auth Success – Profile:', {
      email: profile.Email,
      dbId:  profile.dbId,
      perms: profile.perms
    });

    done(null, profile);
  } catch (err) {
    console.error('Auth callback error', err);
    done(err);
  }
}
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── Routes ────────────────────────────────────────────

// Home
app.get('/', (req, res) => res.render('home', { user: req.user }));

// Kick off login
app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// Callback
app.get(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    // redirect on every login; profile-complete logic can go back here next
    res.redirect('/protected');
  }
);

// Protected example
app.get('/protected', (req, res) => {
  console.log('→ Protected Route - User:', req.user?.Email);
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`Welcome ${req.user.Username}`);
});

// Logout
app.get('/logout', (req, res) =>
  req.logout(() => res.redirect('/'))
);

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
