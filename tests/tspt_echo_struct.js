#!/usr/bin/env node

// An echo service on top of the SSH transport layer. Server and client.
// This version uses the `struct` module to build messages.

var sshiny = require('../');
var struct = sshiny.struct;
var transport = sshiny.transport;

var hello = 'Hello world!';


// Echo service message definitions.
// (These typically go in their own module, where `M` is `exports`.)
var M = {};

var msg = struct.msgModule(M);

msg('echoReq', 192,
  'text', 'string'
);

msg('echoRes', 193,
  'text', 'string'
);


// Message handlers.

// Request handler, sends a response.
M.echoReq.handle = function(tspt, params) {
  tspt.write(M.echoRes, {
    'text': params.text
  });
};

// Response handler, prints the response.
M.echoRes.handle = function(tspt, params) {
  console.log(params.text);
};


// Server.

var server = transport.createServer(function(tspt, name, writer) {
  // Respond to the service request.
  if (name !== 'echo') {
    return writer.reject();
  }
  else {
    writer.accept();
  }

  // Dispatch messages.
  tspt.on('message', function(payload) {
    M.dispatch(tspt, payload);
  });
});

server.listen(60022);


// Client.

var tspt = transport.connect('localhost', 'echo', { port: 60022 }, function() {
  // Send the request message.
  tspt.write(M.echoReq, {
    'text': hello
  });

  // Dispatch messages.
  tspt.on('message', function(payload) {
    M.dispatch(tspt, payload);
  });
});
