const express = require('express');
const pool    = require('../db');
const router  = express.Router();

function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

// GET form
router.get('/complete-profile', ensureLoggedIn, (req, res) => {
  res.render('complete-profile', {
    email:     req.user.Email,
    firstName: '',
    lastName:  '',
    role:      '',
    error:     null
  });
});

// POST submission
router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  const { firstName, lastName, role } = req.body;
  if (!firstName || !lastName || !['viewer','editor','admin'].includes(role)) {
    return res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      error:     'All fields are required and role must be valid.'
    });
  }

  try {
    // 1) Update DB
    await pool.execute(
      `UPDATE users
         SET first_name       = ?,
             last_name        = ?,
             role             = ?,
             profile_complete = 1
       WHERE UserID = ?`,
      [firstName, lastName, role, req.user.UserID]
    );

    // 2) Patch session so banner immediately clears
    req.user.first_name       = firstName;
    req.user.last_name        = lastName;
    req.user.role             = role;
    req.user.profile_complete = true;
    req.user.profileComplete  = true;

    // 3) Audit log (optional)
    await pool.execute(
      `INSERT INTO audit_log (UserID, Action) VALUES (?, 'ProfileCompleted')`,
      [req.user.UserID]
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('complete-profile', {
      email:     req.user.Email,
      firstName, lastName, role,
      error:     'Server error – please try again.'
    });
  }
});

module.exports = router;
