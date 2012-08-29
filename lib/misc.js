var messages = require('./messages');


// As defined in RFC 4253, section 11: “Additional Messages”

var disconnect = messages.register({
  name: 'disconnect',
  id: 1,
  fields: [
    'code', 'uint32',
    'description', 'string',
    'language', 'string'
  ],
  layer: 'transport'
});

var ignore = messages.register({
  name: 'ignore',
  id: 2,
  fields: [],
  layer: 'transport'
});

var unimplemented = messages.register({
  name: 'unimplemented',
  id: 3,
  fields: [
    'seq', 'uint32'
  ],
  layer: 'transport'
});

var debug = messages.register({
  name: 'debug',
  id: 4,
  fields: [
    'alwaysDisplay', 'boolean',
    'message', 'string',
    'language', 'string'
  ],
  layer: 'transport'
});


disconnect.handle = function(tspt, params) {
  // FIXME: handle error
  tspt.stream.destroy();
  return false;
};

ignore.handle = function() {
  // no-op
};

unimplemented.handle = function(tspt, params) {
  // FIXME: emit/log something
};

debug.handle = function(tspt, params) {
  // FIXME: emit/log something
};
