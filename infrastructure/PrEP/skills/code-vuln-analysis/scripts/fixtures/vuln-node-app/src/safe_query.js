// safe_query.js - Safe user lookup endpoint
// Uses parameterized queries to prevent SQL injection
const express = require('express');
const router = express.Router();
const mysql = require('mysql');

const db = mysql.createConnection({
  host: 'localhost', user: 'app', password: 'app_pass', database: 'myapp'
});

router.get('/safe-user', (req, res) => {
  db.query("SELECT * FROM users WHERE name = ?", [req.query.name], (err, rows) => {
    if (err) return res.status(500).json({ error: 'query failed' });
    res.json({ users: rows });
  });
});

module.exports = router;
