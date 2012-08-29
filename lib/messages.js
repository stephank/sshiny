var WalkBuf = require('walkbuf');


// Register a message type.
exports.register = function(message) {
  // Export message by ID and name.
  exports[message.id] = exports[message.name] = message;

  // Create read and write methods.
  var def = exports.createStructDef(message.fields);

  message.read = function(payload) {
    var walk = new WalkBuf(payload, 1);
    var params = def.read(walk);
    var tail = walk.slice();
    if (tail.length !== 0) {
      params['!tail'] = tail;
    }
    return params;
  };

  message.write = function(params) {
    if (!params) {
      params = {};
    }
    def.normalize(params);

    var size = 1 + def.size(params);
    var tail = params['!tail'];
    if (tail) {
      size += tail.length;
    }

    var payload = new Buffer(size);
    var walk = new WalkBuf(payload);
    walk.writeUInt8(message.id);
    def.write(walk, params);
    if (tail) {
      walk.rcopy(tail)
    }

    return payload;
  };

  return message;
};


// Create a structure definition from a description of fields.
exports.createStructDef = function() {
  var def = {};

  var fields = arguments;
  if (Array.isArray(fields[0])) {
    fields = fields[0];
  }

  // FIXME: handle uint64, etc.

  // Read from a WalkBuf.
  def.read = function(walk, offsets) {
    var params = {};
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value;

      if (offsets) {
        offsets.push(walk.pos);
      }

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

        var s = 0;
        while (value[s] === 0) {
          s++;
        }
        if (s !== 0) {
          value = value.slice(s);
        }
      }
      if (type === 'bstring') {
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
  def.normalize = function(params) {
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      if (name === "!skip") {
        continue;
      }
      // Allow a binary string in place of a buffer, because `crypto` currently
      // returns those for big numbers, unfortunately.
      if (typeof(type) === 'number' || type === 'mpint' || type === 'bstring') {
        if (typeof(value) === 'string') {
          value = new Buffer(value, 'binary');
        }
      }

      params[name] = value;
    }
  };

  // Calculate the size for the given parameters.
  def.size = function(params) {
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
      if (type === 'string' || type === 'bstring') {
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

  // Write to a WalkBuf.
  def.write = function(walk, params, offsets) {
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      if (offsets) {
        offsets.push(walk.pos);
      }

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
      if (type === 'bstring') {
        walk.writeUInt32BE(value.length);
        value = walk.rcopy(value);
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

  // Create a buffer for the given params.
  def.create = function(params, offsets) {
    this.normalize(params);
    var buf = new Buffer(this.size(params));
    var walk = new WalkBuf(buf);
    this.write(walk, params, offsets);
    return buf;
  };

  return def;
};


// Dump the buffer as hexadecimals, with `perRow` and `perColumn` specified in
// bytes. Optionally a list of `offsets` can be specified, which will insert
// ANSI escape sequences to alter colouring per field.
exports.dumpHex = function(buf, perRow, perColumn, offsets) {
  // Allow a binary string.
  if (typeof(buf) === 'string') {
    buf = new Buffer(buf, 'binary');
  }

  // Convert to hex.
  var hex = buf.toString('hex');
  perRow *= 2;
  perColumn *= 2;

  // Iterate rows.
  var hi = false;
  var lines = [];
  for (var i = 0; i < hex.length; i += perRow) {
    var slice = hex.slice(i, i + perRow);

    // Iterate columns.
    var line = '';
    for (var j = 0; j < slice.length; j += 2) {

      // Check column end.
      if (j !== 0 && (j % perColumn) === 0) {
        line += ' ';
      }

      // Check field end.
      if (offsets) {
        var pos = (i + j) / 2;
        if (offsets.indexOf(pos) !== -1) {
          hi = !hi;
          if (hi) {
            line += '\033[7m';
          }
          else {
            line += '\033[27m';
          }
        }
      }

      // Add the byte.
      line += slice.slice(j, j + 2);

    }
    // Collect the line.
    lines.push(line);
  }

  // Join lines and reset highlighting.
  var text = lines.join('\n');
  if (hi) {
    text += '\033[22m';
  }

  return text;
};


// These requires are circular, but that's okay. They're here to ensure all
// messages are always registered.
require('./kex');
require('./kexdh');
require('./misc');
