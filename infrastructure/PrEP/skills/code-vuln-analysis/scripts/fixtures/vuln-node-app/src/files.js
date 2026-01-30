// files.js - File download endpoint
// Serves uploaded files to authenticated users

const express = require('express');
const router = express.Router();
const fs = require('fs');

router.get('/download', (req, res) => {
  const filePath = req.query.path;
  if (!filePath) {
    return res.status(400).json({ error: 'path parameter required' });
  }
  fs.readFile('uploads/' + req.query.path, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'file not found' });
    res.send(data);
  });
});

module.exports = router;
