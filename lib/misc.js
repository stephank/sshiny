var messages = require('./messages');


// As defined in RFC 4253, section 11: “Additional Messages”

var disconnect = messages.register({
  name: 'disconnect',
  id: 1,
  fields: [
    'code', 'uint32',
    'description', 'string',
    'language', 'string'
  ]
});

var ignore = messages.register({
  name: 'ignore',
  id: 2,
  fields: []
});

var unimplemented = messages.register({
  name: 'unimplemented',
  id: 3,
  fields: [
    'seq', 'uint32'
  ]
});

var debug = messages.register({
  name: 'debug',
  id: 4,
  fields: [
    'alwaysDisplay', 'boolean',
    'message', 'string',
    'language', 'string'
  ]
});


disconnect.handle = function(tspt, params) {
  // FIXME: handle error
  tspt._stream.destroy();
  return false;
};

ignore.handle = function() {
  // no-op
};

unimplemented.handle = function(tspt, params) {
  // FIXME: emit/log something
};

debug = function(tspt, params) {
  // FIXME: emit/log something
};