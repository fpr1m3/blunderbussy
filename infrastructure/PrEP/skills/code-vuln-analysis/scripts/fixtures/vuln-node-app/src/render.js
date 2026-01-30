// render.js - User greeting endpoint
// Renders a personalized welcome page

const express = require('express');
const router = express.Router();

router.get('/greet', (req, res) => {
  const name = req.query.name;
  if (!name) {
    return res.status(400).send('name parameter required');
  }
  res.setHeader('Content-Type', 'text/html');

  const title = 'Welcome Page';
  const header = '<h1>' + title + '</h1>';
  res.send('<div>' + req.query.name + '</div>');
});

module.exports = router;
