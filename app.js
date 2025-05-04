require('dotenv').config();

console.log(
  `Loaded ENV: Tenant=${process.env.AZURE_AD_B2C_TENANT}` +
  ` Policy=${process.env.AZURE_AD_B2C_POLICY}` +
  ` ClientID=${process.env.AZURE_AD_B2C_CLIENT_ID}` +
  ` Callback=${process.env.CALLBACK_PATH}`
);

const express    = require('express');
const session    = require('express-session');
const passport   = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const morgan     = require('morgan');
const path       = require('path');
const mysql      = require('mysql2/promise');

const PORT = process.env.PORT || 3000;
const app  = express();

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

app.get('/hello', (req, res) => res.send('Hello world'));

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

const azureStrategy = new OIDCStrategy(
  {
    identityMetadata:
      `https://${process.env.AZURE_AD_B2C_TENANT}.b2clogin.com/` +
      `${process.env.AZURE_AD_B2C_TENANT}.onmicrosoft.com/` +
      `${process.env.AZURE_AD_B2C_POLICY}/v2.0/.well-known/openid-configuration`,
    clientID:                 process.env.AZURE_AD_B2C_CLIENT_ID,
    clientSecret:             process.env.AZURE_AD_B2C_CLIENT_SECRET,
    redirectUrl:              `https://${process.env.PUBLIC_HOST}${process.env.CALLBACK_PATH}`,
    allowHttpForRedirectUrl:  process.env.PUBLIC_HOST.startsWith('localhost'),
    responseType:             'code',
    responseMode:             'query',
    scope:                    ['openid','profile','offline_access'],
    validateIssuer:           false
  },
  async (iss, sub, profile, accessToken, refreshToken, done) => {
    try {
      const email = profile.emails[0];
      const name  = profile.displayName || email.split('@')[0];

      // Upsert user
      await pool.execute(
        `INSERT INTO users (Username, Email) VALUES (?, ?)
         ON DUPLICATE KEY UPDATE Username = VALUES(Username)`,
        [name, email]
      );

      // Fetch ID
      const [[userRow]] = await pool.execute(
        `SELECT UserID FROM users WHERE Email = ?`, [email]
      );
      if (!userRow) throw new Error('User not found after upsert');
      profile.dbId = userRow.UserID;

      // Load perms
      const [rows] = await pool.execute(
        `SELECT p.PermissionName
           FROM permissions p
           JOIN rolepermissions rp ON rp.PermissionID = p.PermissionID
           JOIN userroles ur       ON ur.RoleID       = rp.RoleID
          WHERE ur.UserID = ?`,
        [profile.dbId]
      );
      profile.perms = rows.map(r => r.PermissionName);

      done(null, profile);

    } catch (err) {
      console.error('Auth callback error:', err);
      done(err);
    }
  }
);

azureStrategy.name = 'azuread-openidconnect';
console.log('✅  Redirect URI in use:', azureStrategy._config.redirectUrl);
passport.use(azureStrategy);

passport.serializeUser((u, done) => done(null, u.dbId));
passport.deserializeUser(async (id, done) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT UserID, Username, Email FROM users WHERE UserID = ?`, [id]
    );
    done(null, row||false);
  } catch (e) {
    done(e);
  }
});

app.get('/',       (req,res)=>res.render('home',{ user:req.user }));
app.get('/login',  passport.authenticate('azuread-openidconnect',{failureRedirect:'/'}));
app.get(
  process.env.CALLBACK_PATH,
  passport.authenticate('azuread-openidconnect',{failureRedirect:'/'}),
  (req,res)=>res.redirect('/protected')
);

app.get('/protected', (req,res)=>{
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(`
    <h1>Welcome, ${req.user.Username}</h1>
    <p>Permissions: ${req.user.perms.join(', ')}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

app.get('/dashboard',      needPerm('ViewDashboard'),    (req,res)=>res.send('<h2>Dashboard</h2>'));
app.post('/tasks/update',  needPerm('UpdateCareTasks'),  (req,res)=>res.json({success:true}));

app.get('/logout', (req,res,next)=> req.logout(err=> err? next(err): res.redirect('/') ));

app.listen(PORT, ()=> console.log(`Server listening on port ${PORT}`));
