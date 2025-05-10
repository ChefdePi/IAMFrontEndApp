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

// ← your DB pool (not used in this minimal test, but leave it mounted)
const pool         = require('./db');

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
  (iss, sub, profile, accessToken, refreshToken, done) => {
    // minimal: just pass the profile through
    done(null, profile);
  }
));

// ─── Sessions ────────────────────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// home
app.get('/', (req, res) => res.render('home', { user: req.user }));

// login
app.get('/login',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' })
);

// CALLBACK – minimal proof it fired
app.get(callbackPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => {
    console.log('✅  PASSED AUTH CALLBACK – user:', req.user.emails[0]);
    return res.redirect('/dashboard');
  }
);

// require-login helper
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// dashboard
app.get('/dashboard', ensureLoggedIn, (req, res) => {
  res.render('dashboard', { user: req.user });
});

// logout
app.get('/logout', (req, res) =>
  req.logout(() => res.redirect('/'))
);

// start
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
