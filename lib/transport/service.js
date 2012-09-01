var kex = require('./kex');
var M = require('./messages');


// Request a service.
var service = function(tspt, name, writer) {
  if (!writer) {
    return tspt.write(service.bind(this, tspt, name));
  }

  tspt.service = name;
  writer(M.serviceRequest, {
    name: name
  });
};

// Client requests a service.
M.serviceRequest.handle = function(tspt, params) {
  tspt.write(function(writer) {
    // Only the client can send this, and not during a kex. A service request
    // is allowed only once, at the start of a connection.
    if (tspt.role !== 'server' || kex.isPeerInKex(tspt) || tspt.service) {
      writer.unimplemented();
      return;
    }

    // Helper: Accept the request.
    writer.accept = function() {
      writer(M.serviceAccept, {
        name: params.name
      });
      tspt.connected = true;
    };

    // Helper: Reject the request with "Service not available".
    writer.reject = function(message, language) {
      writer.disconnect(7, message || "Service not available");
    };

    // Handle the request. (This triggers the server 'connection' event.)
    tspt.service = params.name;
    tspt.emit('request', params.name, writer);
  });
};

// Server accepts a service.
M.serviceAccept.handle = function(tspt, params) {
  // Only the server can send this, and not during a kex.
  if (tspt.role !== 'client' || kex.isPeerInKex(tspt)) {
    writer.unimplemented();
    return;
  }

  // Check if this was the service we requested.
  if (tspt.service !== params.name) {
    writer.disconnect(0, "Service request and reply don't match");
    return;
  }

  // Start the service.
  tspt.connected = true;
  tspt.emit('connect');
};


module.exports = service;
