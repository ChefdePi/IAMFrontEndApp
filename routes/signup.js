// routes/signup.js
const express = require('express');
const pool    = require('../db');
const router  = express.Router();

function ensureLoggedIn(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');
  next();
}

router.get('/complete-profile', ensureLoggedIn, (req, res) => {
  res.render('complete-profile', {
    email: req.user.Email || req.user.email
  });
});

router.post('/complete-profile', ensureLoggedIn, async (req, res) => {
  try {
    const { firstName, lastName, role } = req.body;
    if (!['Caregiver','FamilyMember'].includes(role)) throw new Error();

    await pool.execute(
      `UPDATE users
         SET first_name=?, last_name=?, role=?, profile_complete=TRUE
       WHERE UserID=?`,
      [firstName, lastName, role, req.user.UserID]
    );
    await pool.execute(
      `INSERT INTO audit_log (UserID, Action) VALUES (?, 'ProfileCompleted')`,
      [req.user.UserID]
    );

    res.redirect('/dashboard');
  } catch {
    res.render('complete-profile', {
      email:     req.user.Email || req.user.email,
      error:     'Please fill in all fields correctly.',
      firstName: req.body.firstName,
      lastName:  req.body.lastName,
      role:      req.body.role
    });
  }
});

module.exports = router;
