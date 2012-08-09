#!/usr/bin/env node

var net = require('net');
var sshiny = require('./');

var tspt = sshiny.connect('localhost');
