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
const host         = rawHost.startsWith('http')
                     ? rawHost
                     : `https://${rawHost}`;
const callbackPath = process.env.CALLBACK_PATH.startsWith('/')
                     ? process.env.CALLBACK_PATH
                     : `/${process.env.CALLBACK_PATH}`;
const redirectUri  = `${host}${callbackPath}`;
console.log('→ Using redirectUri:', redirectUri);

// ─── Middleware ────────────────────────────────────────
app.use(morgan('dev'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
// for form_post on the callback:
app.use(express.urlencoded({ extended: true }));

// ─── Secure Session Cookies ────────────────────────────
app.set('trust proxy', 1);
app.use(session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret-9876',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   true,      // Azure Web Apps is HTTPS
    sameSite: 'Lax',     // CSRF protection
    maxAge:   1000 * 60 * 30
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ─── Mount any sign-up/profile-completion routes ──────
app.use(signupRouter);

// ─── OIDC Strategy (Implicit / ID-token flow) ────────
passport.use('azuread-openidconnect', new OIDCStrategy({
    identityMetadata: 
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:                process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:            process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:             redirectUri,

    // ← IMPLICIT FLOW SETTINGS
    responseType:    'id_token',
    responseMode:    'form_post',
    scope:           ['openid','email','profile'],

    allowHttpForRedirectUrl: host.startsWith('http://'),
    validateIssuer:          false
  },
  // verify callback
  async (iss, sub, profile, _accessToken, _refreshToken, done) => {
    // just log out the raw JSON so you can see if email is present:
    console.log('✅ IMPLICIT CALLBACK – raw profile:', JSON.stringify(profile._json, null,2));
    // for now, skip any DB logic and return the profile
    return done(null, profile);
  }
));

// ─── Session serialization ────────────────────────────
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── Routes ────────────────────────────────────────────

// Home
app.get('/', (req, res) => res.render('home', { user: req.user }));

// Kick off login
app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// ← NB: we must accept POST for form_post
app.post(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    // If you see email in your logs above, you know B2C is sending it.
    // Then you can add your upsert/role-lookup logic here,
    // switch back to code flow, and add offline_access.
    res.redirect('/protected');
  }
);

// Protected example
app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  console.log('→ Protected Route – user JSON:', req.user._json);
  res.send(`Hello ${(req.user._json.email||req.user._json.preferred_username||'user')}!`);
});

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// Start
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
