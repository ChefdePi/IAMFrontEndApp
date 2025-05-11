// routes/signup.js
const express      = require('express');
const pool         = require('../db');
const { logAction } = require('../audit');
const router       = express.Router();

function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// GET “complete your profile” form
router.get('/complete-profile', ensureLoggedIn, async (req, res, next) => {
  try {
    const [roleRows] = await pool.query(
      `SELECT RoleName FROM Roles ORDER BY RoleName`
    );
    const roles = roleRows.map(r => r.RoleName);
    const [firstName = '', lastName = ''] = (req.user.DisplayName || '').split(' ');
    res.render('complete-profile', {
      email:     req.user.Email,
      firstName,
      lastName,
      role:       req.user.role || '',
      roles,
      error:      null
    });
  } catch (err) {
    next(err);
  }
});

// POST the filled-out form
router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  const { firstName, lastName, role } = req.body;
  const [roleRows] = await pool.query(
    `SELECT RoleName FROM Roles ORDER BY RoleName`
  );
  const roles = roleRows.map(r => r.RoleName);

  if (!firstName || !lastName || !roles.includes(role)) {
    return res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      roles,
      error:     'All fields are required, and you must select a valid role.'
    });
  }

  try {
    const displayName = `${firstName} ${lastName}`;

    // Persist DisplayName, first_name, last_name, and mark complete
    await pool.execute(
      `UPDATE Users
          SET DisplayName      = ?,
              first_name       = ?,
              last_name        = ?,
              profile_complete = 1
        WHERE UserID = ?`,
      [displayName, firstName, lastName, req.user.UserID]
    );

    // Assign role
    const [[r]] = await pool.execute(
      `SELECT RoleID FROM Roles WHERE RoleName = ?`,
      [role]
    );
    await pool.execute(
      `DELETE FROM UserRoles WHERE UserID = ?`,
      [req.user.UserID]
    );
    await pool.execute(
      `INSERT INTO UserRoles (UserID, RoleID) VALUES (?, ?)`,
      [req.user.UserID, r.RoleID]
    );

    // Audit
    await logAction({
      userId:    req.user.UserID,
      action:    'COMPLETE_PROFILE',
      entity:    'User',
      entityId:  req.user.UserID,
      details:   { displayName, role }
    });

    // Reload permissions into session
    const [permsRows] = await pool.execute(`
      SELECT p.PermissionName
        FROM Permissions p
        JOIN RolePermissions rp ON rp.PermissionID = p.PermissionID
        JOIN UserRoles ur       ON ur.RoleID       = rp.RoleID
       WHERE ur.UserID = ?`,
      [req.user.UserID]
    );
    req.user.perms           = permsRows.map(r => r.PermissionName);
    req.user.DisplayName     = displayName;
    req.user.first_name      = firstName;
    req.user.last_name       = lastName;
    req.user.profileComplete = true;
    req.user.role            = role;

    res.redirect('/dashboard');
  } catch (err) {
    console.error('❌ Error completing profile:', err);
    res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      roles,
      error:     'Server error — please try again.'
    });
  }
});

module.exports = router;
