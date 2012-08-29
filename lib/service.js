var messages = require('./messages');


// As defined in RFC 4253, section 10: “Service Request”

var serviceRequest = messages.register({
  name: 'serviceRequest',
  id: 5,
  fields: [
    'name', 'string'
  ],
  layer: 'transport'
});

var serviceAccept = messages.register({
  name: 'serviceAccept',
  id: 6,
  fields: [
    'name', 'string'
  ],
  layer: 'transport'
});


// Request a service.
var service = function(tspt, name, writer) {
  if (!writer) {
    return tspt.write(service.bind(this, tspt, name));
  }

  // Request the service.
  tspt._service = name;
  writer('serviceRequest', {
    name: name
  });

  // Start the service.
  // On failure, the server disconnects. So we might as well assume success
  // and give the service a chance to send along further messages.
  var handler = service.registry[name];
  handler(tspt, writer);
};

// Client requests a service.
serviceRequest.handle = function(tspt, params) {
  // Only the client can send this.
  if (tspt.role !== 'server') {
    // FIXME: bail
    return;
  }

  // Check if another service is active.
  if (tspt._service) {
    // FIXME: bail
    return;
  }

  // Check if this service is supported.
  var name = params.name;
  var handler = service.registry[name];
  if (!handler) {
    // FIXME: bail
    return;
  }

  // Accept the service request.
  tspt.write(function(writer) {
    tspt._service = name;
    writer('serviceAccept', {
      name: name
    });

    // Start the service.
    handler(tspt, writer);
  });
};

// Server accepts a service.
serviceAccept.handle = function(tspt, params) {
  // Only the server can send this.
  if (tspt.role !== 'client') {
    // FIXME: bail
    return;
  }

  // Check if this was the service we requested.
  if (tspt._service !== params.name) {
    // FIXME: bail
    return;
  }
};


// Known services by name, and their handlers.
service.registry = {};

// Register a service.
service.register = function(name, handler) {
  service.registry[name] = handler;
};


module.exports = service;


// These requires are circular, but that's okay. They're here to ensure all
// services are always registered.
require('./userauth');
