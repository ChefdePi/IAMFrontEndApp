// routes/reports.js
const express = require('express');
const router  = express.Router();

// GET /reports
router.get('/', (req, res) => {
  res.render('reports', { user: req.user, message: null });
});

// POST /reports
router.post('/', (req, res) => {
  // TODO: save the report…
  res.render('reports', { user: req.user, message: 'Report submitted!' });
});

module.exports = router;
