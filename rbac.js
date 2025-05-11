// rbac.js
const pool = require('./db');

async function getUserPermissions(userId) {
  const [rows] = await pool.query(
    `SELECT p.PermissionName
       FROM UserRoles ur
  JOIN RolePermissions rp ON ur.RoleID = rp.RoleID
  JOIN Permissions p     ON rp.PermissionID = p.PermissionID
      WHERE ur.UserID = ?`,
    [userId]
  );
  return rows.map(r => r.PermissionName);
}

function requirePermission(permission) {
  return async (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }
    const userId = req.user.UserID;
    const perms = await getUserPermissions(userId);
    if (perms.includes(permission)) {
      return next();
    }
    // render your existing forbidden.ejs
    return res.status(403).render('forbidden', { user: req.user });
  };
}

module.exports = { getUserPermissions, requirePermission };
