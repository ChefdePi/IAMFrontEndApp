// routes/permissions.js
const express = require('express');
const pool    = require('../db');
const { requirePermission } = require('../rbac');
const router  = express.Router();

router.get('/', requirePermission('ManageUsers'), async (req, res) => {
  const [permissions] = await pool.query(`SELECT * FROM Permissions`);
  res.render('permissions/index', { permissions });
});

// …add routes for new/edit/delete similarly…
module.exports = router;
