#!/usr/bin/env node

var sshiny = require('./');

var server = sshiny.createServer();
server.listen(60022);

var tspt = sshiny.connect('localhost', { port: 60022 });
