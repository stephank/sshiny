var util = require('util');
var crypto = require('crypto');
var Buffers = require('buffers');
var WalkBuf = require('walkbuf');
var EventEmitter = require('events').EventEmitter;
var messages = require('./messages');

var CR = '\r'.charCodeAt(0);
var LF = '\n'.charCodeAt(0);

var Transport = function(role, stream) {
  var self = this;
  var buffers = new Buffers();

  this.role   = role;
  this.stream = stream;

  this._theirRole = (this.role === 'client' ? 'server' : 'client');

  this._buffers = buffers;
  this._skip = 0;

  this._clientIdent = null;
  this._serverIdent = null;

  this._mac = { size: 0 };

  stream.on('data', function(buf) {
    var offset = buffers.length;
    buffers.push(buf);

    if (self._ondata(buf, offset)) {
      while (self._ondata());
    }
  });

  this._readHandshake();
};
util.inherits(Transport, EventEmitter);
var proto = Transport.prototype;

// Read lines until we encounter a valid handshake.
proto._readHandshake = function() {
  var self = this;
  var buffers = this._buffers;

  var termLength = 1;

  // FIXME: cap handshake length
  this._ondata = function(buf, offset) {
    for (var i = 0; i < buf.length; i++) {
      // Read until \r\n.
      if (buf[i] !== LF) {
        termLength = (buf[i] === CR ? 2 : 1);
        continue;
      }

      // Extract the line, position after line break.
      var chars = offset + i + 1;
      var line = buffers.splice(0, chars);
      offset -= chars;

      // Decode.
      try {
        line = line.toString('utf-8', 0, chars - termLength);
      }
      catch (err) {
        // FIXME: respond? close? more useful error?
        self.emit('error', err);
        self.stream.destroySoon();
        return false;
      }

      // Check for handshake or prelude.
      var match = /^SSH-(.+?)-/.exec(line)
      if (match) {
        // FIXME: check version

        self['_' + self._theirRole + 'Ident'] = line;

        self.emit('handshake', line);
        self._packetLoop();
        return true;
      }
      else {
        self.emit('prelude', line);
      }
    }
    return false;
  }
};

// Read packets.
proto._packetLoop = function() {
  var self = this;
  var buffers = this._buffers;

  // FIXME: cap packet length
  var waitFor = null;
  this._ondata = function() {
    // FIXME: decrypt
    if (waitFor === null) {
      if (buffers.length < 4) {
        return false;
      }

      var data = buffers.slice(0, 4);
      waitFor = 4 + data.readUInt32BE(0) + self._mac.size;
      // FIXME: verify input
    }

    if (buffers.length >= waitFor) {
      var packet = buffers.splice(0, waitFor);
      waitFor = null;
    }
    else {
      return false;
    }
    // FIXME: decrypt

    if (self._mac.size) {
      var mac = packet.slice(packet.length - self._mac.size);
      // FIXME: verify MAC
    }

    var padding = packet.get(4);
    // FIXME: decompress

    if (this._skip) {
      this._skip -= 1;
      return true;
    }

    var type = packet.get(5);
    var message = messages[type];
    if (message) {
      console.log(' <- ', message.name); // FIXME

      var payload = packet.slice(5, packet.length - self._mac.size - padding);
      var walk = new WalkBuf(payload, 1);
      var params = message.read(walk);
      message.handle(self, params, payload);
    }
    else {
      // FIXME: send unimplemented
      console.log('Unknown packet ' + type);
    }

    return true;
  };
};

// Takes a function that uses a writer to send packets.
proto.write = function(block) {
  var self = this;

  // Run block, collect messages and calculate sizes.
  var list = [];
  var dataSize = 0;
  block(function(type, params, callback) {
    var obj = { params: params, callback: callback };
    list.push(obj);

    if (type === 'handshake' || type === 'prelude') {
      obj.message = type;

      dataSize += params.length + 2;
    }
    else {
      var message = messages[type];

      message.normalize(params);

      // FIXME: account for cipher
      var size = 2 + message.size(params);
      var padFactor = 8;
      var padding = (4 + size) % padFactor;
      if (padding !== 0) padding = padFactor - padding;
      if (padding < 4) padding += padFactor;
      obj.padding = padding;
      size += padding;

      obj.message = message;
      obj.size = size;

      dataSize += 4 + obj.size + self._mac.size;
    }
  });

  // Write messages to a buffer.
  var data = new Buffer(dataSize);
  var walk = new WalkBuf(data);
  list.forEach(function(obj) {
    var message = obj.message;
    var payload;

    if (typeof(message) === 'string') {
      if (message === 'handshake') {
        self['_' + self.role + 'Ident'] = obj.params;
      }

      payload = obj.params + '\r\n';
      walk.write(payload);
    }
    else {
      var padding = obj.padding;

      // FIXME: encrypt
      walk.writeUInt32BE(obj.size);
      walk.writeUInt8(padding);

      payloadStart = walk.pos;
      // FIXME: compress
      walk.writeUInt8(message.id);
      message.write(walk, obj.params);
      payload = data.slice(payloadStart, walk.pos);

      walk.rcopy(crypto.randomBytes(padding));
      // FIXME: add MAC

      console.log(' -> ', message.name); // FIXME
    }
    if (obj.callback) {
      obj.callback(payload);
    }
  });

  // All done, send in one shot.
  this.stream.write(data);
};

module.exports = Transport;
