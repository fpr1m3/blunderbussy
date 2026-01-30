// merge.js - Object merge utility endpoint
// Deep merges user-submitted JSON into a configuration object
const express = require('express');
const router = express.Router();

const config = { theme: 'default', lang: 'en' };

function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

router.post('/merge', (req, res) => {
  const result = deepMerge(config, req.body);
  res.json({ status: 'merged', config: result });
});

module.exports = router;
