// routes/signup.js
const express     = require('express');
const pool        = require('../db');
const { logAction } = require('../audit');
const router      = express.Router();

// Ensure the user is authenticated before proceeding
function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  next();
}

// GET the “complete your profile” form
router.get('/complete-profile', ensureLoggedIn, (req, res) => {
  // Pre-split DisplayName ("First Last") into two fields
  const [firstName = '', lastName = ''] = (req.user.DisplayName || '').split(' ');
  res.render('complete-profile', {
    email:     req.user.Email,
    firstName,
    lastName,
    role:      '',
    error:     null
  });
});

// POST the filled-out form
router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  const { firstName, lastName, role } = req.body;
  const validRoles = ['Viewer','Editor','Admin'];

  // 1) Validate inputs
  if (!firstName || !lastName || !validRoles.includes(role)) {
    return res.render('complete-profile', {
      email:     req.user.Email,
      firstName,
      lastName,
      role,
      error:     'All fields are required, and role must be one of Viewer, Editor or Admin.'
    });
  }

  try {
    const displayName = `${firstName} ${lastName}`;

    // 2) Update DisplayName + mark profile_complete
    await pool.execute(
      `UPDATE Users
          SET DisplayName    = ?,
              profile_complete = 1
        WHERE UserID = ?`,
      [displayName, req.user.UserID]
    );

    // 3) Assign the selected role via UserRoles
    // 3a) Find the RoleID
    const [[r]] = await pool.execute(
      `SELECT RoleID FROM Roles WHERE RoleName = ?`,
      [role]
    );
    if (!r) throw new Error(`Role not found: ${role}`);

    // 3b) Remove any old roles
    await pool.execute(
      `DELETE FROM UserRoles WHERE UserID = ?`,
      [req.user.UserID]
    );
    // 3c) Insert the new role mapping
    await pool.execute(
      `INSERT INTO UserRoles (UserID, RoleID) VALUES (?, ?)`,
      [req.user.UserID, r.RoleID]
    );

    // 4) Audit the profile completion
    await logAction({
      userId:    req.user.UserID,
      action:    'COMPLETE_PROFILE',
      entity:    'User',
      entityId:  req.user.UserID,
      details:   { displayName, role }
    });

    // 5) Update session so req.user immediately reflects changes
    req.user.DisplayName    = displayName;
    req.user.profile_complete = true;
    req.user.profileComplete  = true;
    // If you need to refresh perms: reload req.user.perms here.

    // 6) Redirect to dashboard
    res.redirect('/dashboard');

  } catch (err) {
    console.error('❌ Error completing profile:', err);
    res.render('complete-profile', {
      email:     req.user.Email,
      firstName,
      lastName,
      role,
      error:     'Server error — please try again.'
    });
  }
});

module.exports = router;
