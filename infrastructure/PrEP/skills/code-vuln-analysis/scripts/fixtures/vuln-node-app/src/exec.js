// exec.js - Network diagnostic tool
// Pings a host provided by the user via query parameter
const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

router.get('/ping', (req, res) => {
  const host = req.query.host;
  if (!host) {
    return res.status(400).json({ error: 'host parameter required' });
  }
  exec('ping -c 4 ' + req.query.host, (err, stdout) => {
    if (err) return res.status(500).json({ error: 'ping failed' });
    res.json({ output: stdout });
  });
});

module.exports = router;
