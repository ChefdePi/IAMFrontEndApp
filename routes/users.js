// routes/users.js
const express = require('express');
const pool    = require('../db');
const { requirePermission } = require('../rbac');
const router  = express.Router();

// 1. Show “assign roles” form
router.get('/:userId/roles',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { userId } = req.params;
    const [[user]]  = await pool.query('SELECT * FROM Users WHERE UserID=?', [userId]);
    const [allRoles]= await pool.query('SELECT * FROM Roles');
    const [assigned]= await pool.query(
      'SELECT RoleID FROM UserRoles WHERE UserID=?',
      [userId]
    );
    const assignedSet = new Set(assigned.map(r=>r.RoleID));
    res.render('users/roles', { user, allRoles, assignedSet });
});

// 2. Handle “update user’s roles”
router.post('/:userId/roles',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { userId }      = req.params;
    const { roles = [] }  = req.body;      // roles is an array of RoleIDs

    // 2a) clear old assignments
    await pool.query('DELETE FROM UserRoles WHERE UserID=?', [userId]);

    // 2b) insert new ones
    if (roles.length) {
      const rows = roles.map(rid => [userId, rid]);
      await pool.query(
        'INSERT INTO UserRoles (UserID, RoleID) VALUES ?',
        [rows]
      );
    }

    // 2c) audit
    await require('../audit').logAction({
      userId:   req.session.userId,
      action:   'UPDATE',
      entity:   'UserRoles',
      entityId: userId,
      details:  { newRoles: roles }
    });

    res.redirect(`/users/${userId}/roles`);
});

module.exports = router;
