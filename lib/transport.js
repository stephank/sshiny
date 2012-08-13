var util = require('util');
var crypto = require('crypto');
var Buffers = require('buffers');
var EventEmitter = require('events').EventEmitter;
var messages = require('./messages');
var kex = require('./kex');

var CR = '\r'.charCodeAt(0);
var LF = '\n'.charCodeAt(0);
var MAX_SEQ = Math.pow(2, 32) - 1;


// Transport itself handles basic packet reading and writing. But it doubles
// as the main handle for an SSH connection, and is extended by other modules.

var Transport = function(role, stream) {
  var self = this;

  // The role of either side of the connection.
  this.role = role;
  this._theirRole = (this.role === 'client' ? 'server' : 'client');

  // Stream reading attributes.
  var buffers = new Buffers();
  this.stream = stream;
  this._buffers = buffers;
  this._skip = 0;

  // The identification string (SSH-*), stored for the key exchange.
  this._clientIdent = null;
  this._serverIdent = null;

  // Send and receive parameters.
  this._tx = this._rx = {
    // The protocol block size in bytes, which is 8 or the
    // cipher block size, whichever is larger.
    blockSize: 8,
    // The Cipher or Decipher object.
    cipher: null,
    // MAC parameters.
    macAlgo: null,
    macKey: null,
    macSize: 0
  };

  // Sequence numbers.
  this._txSeq = this._rxSeq = -1;

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

  var head = null;
  var waitFor = null;

  this._ondata = function() {
    // Read the packet length.
    if (waitFor === null) {
      // We need to read at least a full block.
      if (buffers.length < this._rx.blockSize) {
        return false;
      }

      // Decrypt and strip off this block.
      head = buffers.splice(0, self._rx.blockSize).toBuffer();
      if (self._rx.cipher) {
        head = self._rx.cipher.update(head);
        head = new Buffer(head, 'binary');
      }

      // Wait for the rest of the packet and the MAC.
      var length = head.readUInt32BE(0);
      waitFor = 4 + length + self._rx.macSize - self._rx.blockSize;
      // FIXME: verify
    }

    // Read the rest of the packet.
    if (buffers.length < waitFor) {
      return false;
    }

    // Increment the sequence number.
    self._rxSeq += 1;
    if (self._rxSeq > MAX_SEQ) {
      self._rxSeq = 0;
    }

    // Decrypt and reassemble the packet.
    var tail = buffers.splice(0, waitFor - self._rx.macSize).toBuffer();
    if (self._rx.cipher) {
      tail = self._rx.cipher.update(tail);
      tail = new Buffer(tail, 'binary');
    }
    var packet = Buffer.concat([head, tail]);
    waitFor = head = null;

    // Verify the MAC.
    if (self._rx.macSize) {
      var theirMac = buffers.splice(self._rx.macSize).toBuffer();

      var seq = new Buffer(4);
      seq.writeUInt32BE(self._rxSeq, 0);

      var mac = crypto.createHmac(self._rx.macAlgo, self._rx.macKey);
      mac.update(seq);
      mac.update(packet);
      mac = new Buffer(mac.digest(), 'binary');

      // FIXME: compare
    }

    // Get just the payload.
    var padding = packet[4];
    var payload = packet.slice(5, packet.length - padding);

    // Decompress.
    if (self._rx.compress) {
      // FIXME
    }

    // Skip this packet, if requested. (E.g. a key exchange guess packet.)
    if (self._skip) {
      self._skip -= 1;
      return true;
    }

    // Dispatch.
    var type = payload[0];
    var message = messages[type];
    if (message) {
      console.log(' <- ', message.name); // FIXME

      var params = message.read(payload);
      if (message.handle(self, params, payload) === false) {
        return false;
      }
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

  var list = [];
  block(function(type, params) {
    var payload;

    // Prelude handling.
    if (type === 'handshake' || type === 'prelude') {
      // Store the identification string.
      if (type === 'handshake') {
        self['_' + self.role + 'Ident'] = params;
      }

      // Encode to a buffer.
      payload = new Buffer(params + '\r\n', 'utf-8');
      list.push(payload);
    }
    // Message handling.
    else {
      // Increment the sequence number.
      self._txSeq += 1;
      if (self._txSeq > MAX_SEQ) {
        self._txSeq = 0;
      }

      // Build the payload.
      var message = messages[type];
      payload = message.write(params);

      console.log(' -> ', message.name); // FIXME

      // Compress.
      if (self._tx.compress) {
        // FIXME
      }

      // Create padding.
      var blockSize = self._tx.blockSize;
      var p = (5 + payload.length) % blockSize;
      if (p !== 0) p = blockSize - p;
      if (p < 4) p += blockSize;
      var padding = crypto.randomBytes(p);

      // Build the packet.
      var lengths = new Buffer(5);
      lengths.writeUInt32BE(1 + payload.length + p, 0);
      lengths.writeUInt8(p, 4);
      var packet = Buffer.concat([lengths, payload, padding]);

      // Calculate the MAC.
      var mac;
      if (self._tx.macSize) {
        var seq = new Buffer(4);
        seq.writeUInt32BE(self._txSeq, 0);

        mac = crypto.createHmac(self._tx.macAlgo, self._tx.macKey);
        mac.update(seq);
        mac.update(packet);
        mac = new Buffer(mac.digest(), 'binary');
      }

      // Encrypt.
      if (self._tx.cipher) {
        packet = self._tx.cipher.update(packet);
        packet = new Buffer(packet, 'binary');
      }

      // Push to the buffer list.
      list.push(packet);
      if (mac) {
        list.push(mac);
      }
    }
    return payload;
  });

  // All done, send in one shot.
  if (list.length) {
    this.stream.write(Buffer.concat(list));
  }
};

// Start the handshake and setup a secure connection.
// Takes an optional callback when the connection becomes secure. This
// callback receives a writer.
proto._start = function(secureCb) {
  var self = this;

  if (secureCb) {
    this.on('secure', secureCb);
  }

  this.write(function(writer) {
    writer('handshake', 'SSH-2.0-sshiny_' + exports.version);
    kex(self, writer);
  });
};


module.exports = Transport;
