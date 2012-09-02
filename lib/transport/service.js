var kex = require('./kex');
var M = require('./messages');


// Request a service.
var service = function(tspt, name) {
  tspt.service = name;
  tspt.write(M.serviceRequest, {
    name: name
  });
};

// Client requests a service.
M.serviceRequest.handle = function(tspt, params) {
  // Only the client can send this, and not during a kex. A service request
  // is allowed only once, at the start of a connection.
  if (tspt.role !== 'server' || kex.isPeerInKex(tspt) || tspt.service) {
    return tspt.unimplemented();
  }

  // Helper: Accept the request.
  tspt.accept = function() {
    this.write(M.serviceAccept, {
      name: params.name
    });
    tspt.connected = true;
  };

  // Helper: Reject the request with "Service not available".
  tspt.reject = function(message, language) {
    this.disconnect(7, message || "Service not available");
  };

  // Handle the request. (This triggers the server 'connection' event.)
  tspt.service = params.name;
  tspt.emit('request', params.name);
};

// Server accepts a service.
M.serviceAccept.handle = function(tspt, params) {
  // Only the server can send this, and not during a kex.
  if (tspt.role !== 'client' || kex.isPeerInKex(tspt)) {
    return tspt.unimplemented();
  }

  // Check if this was the service we requested.
  if (tspt.service !== params.name) {
    tspt.disconnect(0, "Service request and reply don't match");
  }

  // Start the service.
  tspt.connected = true;
  tspt.emit('connect');
};


module.exports = service;
