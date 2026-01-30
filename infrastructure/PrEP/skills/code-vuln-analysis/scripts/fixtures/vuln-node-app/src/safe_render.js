// safe_render.js - Safe user greeting endpoint
// Renders a personalized welcome page with proper escaping

const express = require('express');
const router = express.Router();

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

router.get('/safe-greet', (req, res) => {
  res.send('<div>' + escapeHtml(req.query.name) + '</div>');
});

module.exports = router;
