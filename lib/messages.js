// Register a message type.
exports.register = function(message) {
  var fields = message.fields;

  // Export message by ID and name.
  exports[message.id] = exports[message.name] = message;

  // FIXME: handle uint64, etc.

  // Read the message from a WalkBuf.
  message.read = function(walk) {
    var params = {};
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value;

      if (name === "!skip") {
        walk.skip(type);
        continue;
      }
      if (typeof(type) === 'number') {
        value = walk.slice(type);
      }
      if (type === 'uint32') {
        value = walk.readUInt32BE();
      }
      if (type === 'boolean') {
        value = walk.readUInt8() != 0;
      }
      if (type === 'mpint') {
        var length = walk.readUInt32BE();
        value = walk.slice(length);
      }
      if (type === 'string' || type === 'name-list') {
        var length = walk.readUInt32BE();
        value = walk.toString('utf-8', length);
      }
      if (type === 'name-list') {
        value = value ? value.split(',') : [];
      }

      params[name] = value;
    }
    return params;
  };

  // Normalize parameters.
  message.normalize = function(params) {
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      // Allow a binary string for `mpint`, which is what `crypto` currently
      // returns for big numbers, unfortunately.
      if (type === 'mpint' && typeof(value) === 'string') {
        value = new Buffer(value, 'binary');
      }

      params[name] = value;
    }
  };

  // Calculate the message size for the given parameters.
  message.size = function(params) {
    var size = 0;
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      if (typeof(type) === 'number') {
        size += type;
      }
      if (type === 'uint32') {
        size += 4;
      }
      if (type === 'boolean') {
        size += 1;
      }
      if (type === 'mpint') {
        size += 4 + value.length;
        if (value[0] & 0x80) {
          size += 1;
        }
      }
      if (type === 'string') {
        size += 4 + value.length;
      }
      if (type === 'name-list') {
        size += 4;
        if (value.length) {
          size += value.length - 1;
          value.forEach(function(x) {
            size += x.length;
          });
        }
      }
    }
    return size;
  };

  // Write the message to a WalkBuf.
  message.write = function(walk, params) {
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      if (name === "!skip") {
        walk.fill(0, type);
        continue;
      }
      if (typeof(type) === 'number') {
        walk.rcopy(value, 0, type);
      }
      if (type === 'uint32') {
        walk.writeUInt32BE(value);
      }
      if (type === 'boolean') {
        walk.writeUInt8(value ? 1 : 0);
      }
      if (type === 'mpint') {
        var leading = ((value[0] & 0x80) ? 1 : 0);
        walk.writeUInt32BE(value.length + leading);
        if (leading) {
          walk.writeInt8(0);
        }
        walk.rcopy(value);
      }
      if (type === 'name-list') {
        value = value.join(',');
      }
      if (type === 'string' || type === 'name-list') {
        walk.writeUInt32BE(value.length);
        walk.write(value, value.length, 'utf-8');
      }
    }
  };

  return message;
};

// These requires are circular, but that's okay. They're here to ensure all
// messages are always registered.
require('./kex');
require('./kexdh');
