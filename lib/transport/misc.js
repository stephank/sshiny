var messages = require('./messages');


messages.disconnect.handle = function(tspt, params) {
  // FIXME: handle error
  tspt.stream.destroy();
  return false;
};

messages.ignore.handle = function() {
  // no-op
};

messages.unimplemented.handle = function(tspt, params) {
  // FIXME: emit/log something
};

messages.debug.handle = function(tspt, params) {
  // FIXME: emit/log something
};
