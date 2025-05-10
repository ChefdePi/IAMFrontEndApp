const express = require('express');
const pool    = require('../db');
const router  = express.Router();

// Show the “finish your profile” form
router.get('/complete-profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  res.render('complete-profile', {
    email:     req.user.Email,
    firstName: '',
    lastName:  '',
    role:      '',
    error:     null
  });
});

// Handle the form POST
router.post('/complete-profile', async (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const { firstName, lastName, role } = req.body;
  // Validate: you can adjust the allowed roles as needed
  if (
    !firstName ||
    !lastName ||
    !['unapproved','viewer','editor','admin'].includes(role)
  ) {
    return res.render('complete-profile', {
      email:     req.user.Email,
      error:     'All fields are required and role must be valid.',
      firstName, lastName, role
    });
  }

  try {
    // Update their profile and flip on “complete”
    await pool.execute(
      `UPDATE users
         SET first_name      = ?,
             last_name       = ?,
             role            = ?,
             profile_complete = 1
       WHERE UserID = ?`,
      [firstName, lastName, role, req.user.UserID]
    );
    // Redirect into the protected area
    res.redirect('/protected');
  } catch (err) {
    console.error(err);
    res.render('complete-profile', {
      email:     req.user.Email,
      error:     'Server error – please try again.',
      firstName, lastName, role
    });
  }
});

module.exports = router;
