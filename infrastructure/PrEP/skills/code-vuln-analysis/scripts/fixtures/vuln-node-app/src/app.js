// app.js - Express application entry point
// Sets up middleware and registers route handlers

const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const merge = require('./merge');
const exec = require('./exec');
const render = require('./render');
const query = require('./query');
const files = require('./files');
const compute = require('./compute');

app.use(merge);
app.use(exec);
app.use(render);
app.use(query);
app.use(files);
app.use(compute);

const config = require('./config');
app.listen(config.port, () => {
  console.log('Server running on port ' + config.port);
});

module.exports = app;
