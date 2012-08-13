#!/usr/bin/env node

var sshiny = require('./');

var host = process.argv[2] || 'localhost'
var tspt = sshiny.connect(host);
