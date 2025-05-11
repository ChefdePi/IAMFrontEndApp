// ─── routes/signup.js ───────────────────────────────────────────────
const express     = require('express');
const pool        = require('../db');
const { logAction } = require('../audit');
const router      = express.Router();

function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  next();
}

// GET form
router.get('/complete-profile', ensureLoggedIn, (req, res) => {
  res.render('complete-profile', {
    email:     req.user.Email,
    firstName: req.user.first_name || '',
    lastName:  req.user.last_name  || '',
    role:      req.user.role       || '',
    error:     null
  });
});

// POST form
router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  const { firstName, lastName, role } = req.body;
  const validRoles = ['Viewer','Editor','Admin'];

  if (!firstName || !lastName || !validRoles.includes(role)) {
    return res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      error:     'All fields are required, and you must select a valid role.'
    });
  }

  try {
    // Update user
    await pool.execute(
      `UPDATE users
          SET first_name       = ?,
              last_name        = ?,
              role             = ?,
              profile_complete = 1
        WHERE UserID = ?`,
      [ firstName, lastName, role, req.user.UserID ]
    );

    // Patch session
    Object.assign(req.user, {
      first_name:       firstName,
      last_name:        lastName,
      role,
      profile_complete: true,
      profileComplete:  true
    });

    // Audit
    await logAction({
      userId:    req.user.UserID,
      action:    'COMPLETE_PROFILE',
      entity:    'User',
      entityId:  req.user.UserID,
      details:   { firstName, lastName, role }
    });

    res.redirect('/dashboard');
  } catch (err) {
    console.error('❌ Error completing profile:', err);
    res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      error:     'Server error – please try again.'
    });
  }
});

module.exports = router;
