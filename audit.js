// audit.js
const pool = require('./db');

async function logAction({ userId, action, entity, entityId, details }) {
  await pool.query(
    `INSERT INTO AuditLogs (UserID, Action, Entity, EntityID, Details)
         VALUES (?, ?, ?, ?, ?)`,
    [userId, action, entity, entityId, JSON.stringify(details)]
  );
}

module.exports = { logAction };
