require('dotenv').config();

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
//Added the one below for ejs too
const path = require('path');

const app = express();
const PORT = 3000;
//New stuff for ejs
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware (stores login sessions)
app.use(
  session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport with Azure OIDC strategy
passport.use(
  new OIDCStrategy(
    {
      identityMetadata: `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0/.well-known/openid-configuration`,
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      responseType: 'code',
      responseMode: 'query',
      redirectUrl: process.env.REDIRECT_URI,
      allowHttpForRedirectUrl: true,
      scope: ['profile', 'offline_access', 'https://graph.microsoft.com/user.read'],
    },
    function (iss, sub, profile, accessToken, refreshToken, done) {
      // This function gets called when login is successful
      return done(null, profile);
    }
  )
);

// Serialize/deserialize user for session storage
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Routes

// Home page ejs 
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

// Login route
app.get('/login', passport.authenticate('azuread-openidconnect'));

// Redirect/callback URL (after Azure login)
app.get(
  '/auth/openid/return',
  passport.authenticate('azuread-openidconnect', {
    failureRedirect: '/',
  }),
  (req, res) => {
    res.redirect('/protected');
  }
);

// Protected route
app.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }

  res.send(`
    <h1>Logged in successfully!</h1>
    <p>Welcome, ${req.user.displayName}</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});