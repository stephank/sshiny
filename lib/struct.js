var WalkBuf = require('walkbuf');


// Create a structure definition from a description of fields.
var struct = module.exports = function(fields) {
  if (!Array.isArray(fields)) {
    fields = Array.prototype.slice.call(arguments, 0);
  }

  var def = {};

  // FIXME: handle uint64, etc.

  // Read from a Buffer or WalkBuf.
  def.read = function(walk, offsets) {
    if (Buffer.isBuffer(walk)) {
      walk = new WalkBuf(walk);
    }

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
      if (name === "!tail") {
        walk.slice();
      }
      if (typeof(type) === 'number') {
        value = walk.slice(type);
      }
      if (type === 'byte') {
        value = walk.readUInt8();
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
    if (!params) {
      params = {};
    }

    if (params._normalized) {
      return params;
    }
    else {
      params = Object.create(params, {
        _normalized: { value: true }
      });
    }

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

    return params;
  };

  // Calculate the size for the given parameters.
  def.size = function(params) {
    params = this.normalize(params);

    var size = 0;
    for (var i = 0; i < fields.length; i += 2) {
      var name = fields[i];
      var type = fields[i+1];
      var value = params[name];

      if (name === "!skip") {
        size += type;
        continue;
      }
      if (name === "!tail") {
        size += value.length;
      }
      if (typeof(type) === 'number') {
        size += type;
      }
      if (type === 'byte') {
        size += 1;
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

  // Write to a Buffer or WalkBuf. If `null` is supplied, creates a Buffer.
  def.write = function(walk, params, offsets) {
    var ret;

    params = this.normalize(params);
    if (walk == null) {
      ret = walk = new Buffer(this.size(params));
    }
    if (Buffer.isBuffer(walk)) {
      walk = new WalkBuf(walk);
    }

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
      if (name === "!tail") {
        walk.rcopy(value);
      }
      if (typeof(type) === 'number') {
        walk.rcopy(value, 0, type);
      }
      if (type === 'byte') {
        walk.writeUInt8(value);
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

    return ret;
  };

  return def;
};


// A message is just a struct with an ID in front.
struct.msg = function(id, fields) {
  if (!Array.isArray(fields)) {
    fields = Array.prototype.slice.call(arguments, 1);
  }
  fields = ['id', 'byte'].concat(fields);

  var def = struct(fields);
  def.id = id;

  // Set the ID when normalizing params.
  var origNormalize = def.normalize;
  def.normalize = function(params) {
    params = origNormalize.call(this, params);
    params.id = id;
    return params;
  };

  return def;
};


// Several parts of the protocol define messages separately. In some
// situations even, one ID can mean several things. (Different kex methods,
// userauth methods, or private use messages.)
//
// Convention is to separate each of these parts in a directory, and have a
// `messages` module that defines and exports messages by ID and a short name.
//
// This returns a function that helps in defining those messages and exporting
// them on the given object (usually the `exports` of the module).
struct.msgModule = function(obj) {
  var builder = function(name, id) {
    var fields = Array.prototype.slice.call(arguments, 2);

    var def = struct.msg(id, fields);
    def.name = name;

    obj[name] = obj[id] = def;
    return def;
  };

  // Dispatch to `handle` methods added to message definitions.
  obj.dispatch = function(tspt, payload) {
    var type = payload[0];
    var message = obj[type];
    if (!message) {
      tspt.unimplemented();
    }
    else {
      console.log(' <- ', message.name); // FIXME

      // FIXME: handle failure to read
      var params = message.read(payload);
      message.handle(tspt, params, payload);
    }
  };

  return builder;
};
