// routes/roles.js
const express = require('express');
const pool    = require('../db');
const { requirePermission } = require('../rbac');
const router  = express.Router();

// 1. List all roles
router.get('/', 
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const [roles] = await pool.query('SELECT * FROM Roles');
    res.render('roles/index', { roles });
});

// 2. Show “new role” form (with checkboxes for Permissions)
router.get('/new',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const [perms] = await pool.query('SELECT * FROM Permissions');
    res.render('roles/new', { perms });
});

// 3. Handle “create role”
router.post('/',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { roleName, description, permissions = [] } = req.body;
    // 3a) create the role
    const [r] = await pool.query(
      'INSERT INTO Roles (RoleName, Description) VALUES (?, ?)',
      [roleName, description]
    );
    const newRoleId = r.insertId;

    // 3b) assign its permissions
    if (permissions.length) {
      const rows = permissions.map(pid => [newRoleId, pid]);
      await pool.query(
        'INSERT INTO RolePermissions (RoleID, PermissionID) VALUES ?',
        [rows]
      );
    }

    // 3c) audit it
    await require('../audit').logAction({
      userId:   req.session.userId,
      action:   'CREATE',
      entity:   'Role',
      entityId: newRoleId,
      details:  { roleName }
    });

    res.redirect('/roles');
});

// 4. Edit role + its perms
router.get('/:roleId/edit',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { roleId } = req.params;
    const [[role]]  = await pool.query('SELECT * FROM Roles WHERE RoleID=?', [roleId]);
    const [perms]   = await pool.query('SELECT * FROM Permissions');
    const [assigned]= await pool.query(
      'SELECT PermissionID FROM RolePermissions WHERE RoleID=?',
      [roleId]
    );
    const assignedSet = new Set(assigned.map(r=>r.PermissionID));
    res.render('roles/edit', { role, perms, assignedSet });
});

// 5. Handle “update role”
router.put('/:roleId',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { roleId } = req.params;
    const { roleName, description, permissions = [] } = req.body;

    // 5a) update the role
    await pool.query(
      'UPDATE Roles SET RoleName=?, Description=?, UpdatedAt=NOW() WHERE RoleID=?',
      [roleName, description, roleId]
    );

    // 5b) swap out its permissions
    await pool.query('DELETE FROM RolePermissions WHERE RoleID=?', [roleId]);
    if (permissions.length) {
      const rows = permissions.map(pid => [roleId, pid]);
      await pool.query(
        'INSERT INTO RolePermissions (RoleID, PermissionID) VALUES ?',
        [rows]
      );
    }

    // 5c) audit it
    await require('../audit').logAction({
      userId:   req.session.userId,
      action:   'UPDATE',
      entity:   'Role',
      entityId: roleId,
      details:  { roleName }
    });

    res.redirect('/roles');
});

// 6. Delete role
router.delete('/:roleId',
  requirePermission('ManageUsers'),
  async (req, res, next) => {
    const { roleId } = req.params;
    await pool.query('DELETE FROM Roles WHERE RoleID=?', [roleId]);
    await require('../audit').logAction({
      userId:   req.session.userId,
      action:   'DELETE',
      entity:   'Role',
      entityId: roleId,
      details:  {}
    });
    res.redirect('/roles');
});

module.exports = router;
