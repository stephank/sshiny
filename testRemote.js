#!/usr/bin/env node

var sshiny = require('./');

var host = process.argv[2] || 'localhost';
var port = process.argv[3] || '22';

var tspt = sshiny.transport.connect(host, 'ssh-connection', { port: parseInt(port, 10) });
