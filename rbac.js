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
    const userId = req.session.userId;
    const perms  = await getUserPermissions(userId);
    if (perms.includes(permission)) return next();
    res.status(403).render('errors/403');
  };
}

module.exports = { getUserPermissions, requirePermission };
