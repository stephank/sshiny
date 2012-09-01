#!/usr/bin/env node

var sshiny = require('./');

var server = sshiny.transport.createServer(function(conn, name, writer) {
  if (name !== 'ssh-connection') {
    writer.reject();
    return;
  }

  writer.accept();
  // ...
});
server.listen(60022);

sshiny.transport.connect('localhost', 'ssh-connection', { port: 60022 }, function() {
  // ...
});
