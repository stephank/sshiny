#!/usr/bin/env node

// An echo service on top of the SSH transport layer. Server and client.
// This version uses Buffers to build messages.

var sshiny = require('../');
var transport = sshiny.transport;

var hello = 'Hello world!';


// Server.

var server = transport.createServer(function(tspt, name, writer) {
  // Respond to the service request.
  if (name !== 'echo') {
    return writer.reject();
  }
  else {
    writer.accept();
  }

  // Echo back messages verbatim.
  tspt.on('message', function(payload) {
    tspt.write(payload);
  });
});

server.listen(60022);


// Client.

var tspt = transport.connect('localhost', 'echo', { port: 60022 }, function() {
  // Send the message. Note that the first byte must be a message ID.
  var payload = new Buffer(1 + hello.length);
  payload[0] = 192;
  payload.write(hello, 1);
  tspt.write(payload);

  // Print echos.
  tspt.on('message', function(payload) {
    if (payload[0] === 192) {
      console.log(payload.toString('utf-8', 1));
    }
  });
});
