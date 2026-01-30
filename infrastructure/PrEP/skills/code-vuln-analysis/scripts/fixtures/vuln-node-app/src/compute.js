// compute.js - Server-side expression evaluator
// Evaluates mathematical expressions submitted by users

const express = require('express');
const router = express.Router();

router.post('/compute', (req, res) => {
  if (!req.body.expression) {
    return res.status(400).json({ error: 'expression required' });
  }
  const result = new Function('return ' + req.body.expression)();
  res.json({ result: result });
});

module.exports = router;
