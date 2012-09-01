var M = require('./messages');


M.disconnect.handle = function(tspt, params) {
  // FIXME: handle error
  tspt.stream.destroy();
  return false;
};

M.ignore.handle = function() {
  // no-op
};

M.unimplemented.handle = function(tspt, params) {
  // FIXME: emit/log something
};

M.debug.handle = function(tspt, params) {
  // FIXME: emit/log something
};
