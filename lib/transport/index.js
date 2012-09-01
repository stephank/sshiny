var util = require('util');
var crypto = require('crypto');
var Buffers = require('buffers');
var EventEmitter = require('events').EventEmitter;
var kex = require('./kex');
var M = require('./messages');

var CR = '\r'.charCodeAt(0);
var LF = '\n'.charCodeAt(0);
var MAX_SEQ = Math.pow(2, 32) - 1;

exports.version = require('../../package.json').version;


// Implements the SSH Transport Layer Protocol, as defined in RFC 4253.
//
// This basically provides functionality similar to TLS, but in a message based
// protocol. (E.g. server authentication, confidentiality and data integrity.)
//
// This module deals with basic packet reading and writing. Other modules in
// the `transport` directory can be seen as mixins implementing the other parts
// of the protocol.
var Transport = function(role, stream, options) {
  this.options = options || {};

  // The role of either side of the connection.
  this.role = role;
  this._theirRole = (this.role === 'client' ? 'server' : 'client');

  // Stream reading attributes.
  this.stream = stream;
  this._buffers = new Buffers();
  this._skip = 0;
  this._ondata = null;

  // The identification string (SSH-*), stored for the key exchange.
  this._clientIdent = null;
  this._serverIdent = null;

  // Key exchange state.
  this._kex = null;
  this._kexMethod = null;
  this._queue = null;

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
};
util.inherits(Transport, EventEmitter);
var proto = Transport.prototype;

// Start the SSH protocol on the stream.
proto._start = function(after) {
  var self = this;
  var stream = this.stream;
  var buffers = this._buffers;

  // Data received is appended to a buffer chain.
  this.stream.on('data', function(buf) {
    var offset = buffers.length;
    buffers.push(buf);

    // Try to flush as much of the buffer as possible.
    var res = self._ondata(buf, offset);
    while (res && stream.readable && stream.writable) {
      res = self._ondata();
    }
  });

  // Start with the handshake and key exchange.
  this._readHandshake();
  this.write(function(writer) {
    writer._line('SSH-2.0-sshiny_' + exports.version, true);
    kex(self, writer);

    if (after) {
      after(writer);
    }
  });
};

// Read lines until we encounter a valid handshake.
proto._readHandshake = function() {
  var self = this;
  var buffers = this._buffers;

  var termLength = 1;

  // FIXME: cap line length.
  this._ondata = function(buf, offset) {
    for (var i = 0; i < buf.length; i++) {
      // Read until CRLF.
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
      if (!match) {
        self.emit('prelude', line);
      }
      else {
        // FIXME: check version

        self['_' + self._theirRole + 'Ident'] = line;

        self.emit('handshake', line);
        self._packetLoop();
        return true;
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
    var rx = self._rx;

    // Read the packet length.
    if (waitFor === null) {
      // We need to read at least a full block.
      if (buffers.length < rx.blockSize) {
        return false;
      }

      // Decrypt and strip off this block.
      head = buffers.splice(0, rx.blockSize).toBuffer();
      if (rx.cipher) {
        head = rx.cipher.update(head);
        head = new Buffer(head, 'binary');
      }

      // Wait for the rest of the packet and the MAC.
      var length = head.readUInt32BE(0);
      waitFor = 4 + length + rx.macSize - rx.blockSize;
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
    var tail = buffers.splice(0, waitFor - rx.macSize).toBuffer();
    var packet;
    if (waitFor === rx.macSize) {
      packet = head;
    }
    else {
      if (rx.cipher) {
        tail = rx.cipher.update(tail);
        tail = new Buffer(tail, 'binary');
      }
      packet = Buffer.concat([head, tail]);
    }
    waitFor = head = null;

    // Verify the MAC.
    if (rx.macSize) {
      var theirMac = buffers.splice(0, rx.macSize).toBuffer();

      var seq = new Buffer(4);
      seq.writeUInt32BE(self._rxSeq, 0);

      var mac = crypto.createHmac(rx.macAlgo, rx.macKey);
      mac.update(seq);
      mac.update(packet);
      mac = new Buffer(mac.digest(), 'binary');

      // FIXME: compare
    }

    // Get just the payload.
    var padding = packet[4];
    var payload = packet.slice(5, packet.length - padding);

    // Decompress.
    if (rx.compress) {
      // FIXME
    }

    // Skip this packet, if requested. (E.g. a key exchange guess packet.)
    if (self._skip) {
      self._skip -= 1;
      return true;
    }

    // Emit non-transport messages.
    var type = payload[0];
    if (type >= 50) {
      // Not allowed between their kexinit and newkeys.
      if (kex.isPeerInKex(self)) {
        self.write(function(writer) {
          writer.unimplemented();
        });
      }
      else {
        self.emit('message', payload);
      }
    }

    // Dispatch method-specific kex messages.
    else if (type >= 30) {
      var method = self._kexMethod;
      if (!method) {
        self.write(function(writer) {
          writer.unimplemented();
        });
      }
      else {
        method.handle(self, payload);
      }
    }

    // Dispatch regular transport messages.
    else {
      M.dispatch(self, payload);
    }

    return true;
  };
};

// Takes a function that uses a writer to send packets.
proto.write = function(block) {
  var self = this;
  var stream = self.stream;

  var list = [];
  var willDisconnect = false;

  var writer = function(message, params, callback) {
    // Queue certain writes while we're in a key exchange.
    if (kex.isInKex(self) && (message.id >= 50 || message === M.kexinit ||
        message === M.serviceRequest || message === M.serviceAccept)) {
      var queue = self._queue;
      if (!queue) {
        queue = self._queue = [];
      }
      queue.push(arguments);
      return;
    }

    console.log(' -> ', message.name); // FIXME

    // Is this a disconnect? Make it the last message.
    if (willDisconnect || !stream.writable) {
      return;
    }
    else if (message === M.disconnect) {
      willDisconnect = true;
    }

    // Increment the sequence number.
    self._txSeq += 1;
    if (self._txSeq > MAX_SEQ) {
      self._txSeq = 0;
    }

    // Build the payload.
    var payload = message.write(null, params);
    var tx = self._tx;

    // Compress.
    if (tx.compress) {
      // FIXME
    }

    // Create padding.
    var blockSize = tx.blockSize;
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
    if (tx.macSize) {
      var seq = new Buffer(4);
      seq.writeUInt32BE(self._txSeq, 0);

      mac = crypto.createHmac(tx.macAlgo, tx.macKey);
      mac.update(seq);
      mac.update(packet);
      mac = new Buffer(mac.digest(), 'binary');
    }

    // Encrypt.
    if (tx.cipher) {
      packet = tx.cipher.update(packet);
      packet = new Buffer(packet, 'binary');
    }

    // Push to the buffer list.
    list.push(packet);
    if (mac) {
      list.push(mac);
    }

    // Return the payload.
    if (callback) {
      callback(payload);
    }
  };

  // Push a line of text. Only used internally for the handshake.
  writer._line = function(line, isHandshake) {
    // Store the identification string.
    if (isHandshake) {
      self['_' + self.role + 'Ident'] = line;
    }

    // Encode to a buffer.
    payload = new Buffer(line + '\r\n', 'utf-8');
    list.push(payload);
  };

  // Flush the write queue. Only used internally for the handshake.
  writer._flush = function() {
    var queue = self._queue;
    if (queue) {
      self._queue = null;
      queue.forEach(function(args) {
        writer(args[0], args[1], args[2]);
      });
    }
  };

  // Helper: Reply with disconnect and end the stream.
  writer.disconnect = function(code, description, language) {
    writer(M.disconnect, {
      'code': code || 0,
      'description': description || '',
      'language': language || ''
    });
  };

  // Helper: Reply with unimplemented to the current rxSeq.
  writer.unimplemented = function() {
    writer(M.unimplemented, {
      'seq': self._rxSeq
    });
  };

  // Send in one shot.
  block(writer);
  if (list.length) {
    stream.write(Buffer.concat(list));
    if (willDisconnect) {
      stream.destroySoon();
    }
  }
};


module.exports = Transport;
