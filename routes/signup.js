const express = require('express');
const pool    = require('../db');
const router  = express.Router();

function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

router.get('/complete-profile', ensureLoggedIn, (req, res) => {
  res.render('complete-profile', {
    email:     req.user.Email || req.user.email,
    firstName: '',
    lastName:  '',
    role:      '',
    error:     null
  });
});

router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  const { firstName, lastName, role } = req.body;
  if (!firstName || !lastName || !['Caregiver','FamilyMember'].includes(role)) {
    return res.render('complete-profile', {
      email:     req.user.Email || req.user.email,
      error:     'All fields are required and role must be valid.',
      firstName, lastName, role
    });
  }

  try {
    // Update profile and mark complete
    await pool.execute(
      `UPDATE users
         SET first_name      = ?,
             last_name       = ?,
             role            = ?,
             profile_complete = 1
       WHERE UserID = ?`,
      [firstName, lastName, role, req.user.UserID]
    );
    // optional audit trail
    await pool.execute(
      `INSERT INTO audit_log (UserID, Action) VALUES (?, 'ProfileCompleted')`,
      [req.user.UserID]
    );
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('complete-profile', {
      email:     req.user.Email || req.user.email,
      error:     'Server error – please try again.',
      firstName, lastName, role
    });
  }
});

module.exports = router;
