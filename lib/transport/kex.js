var crypto = require('crypto');
var WalkBuf = require('walkbuf');
var struct = require('../struct');
var messages = require('./messages');
var kexdh = require('./kexdh');


// Build data used as keys for the encryption and authentication algorithms.
var buildKeyData = function(tspt, x, amount) {
  var out = new Buffer(amount);
  var walk = new WalkBuf(out);

  // This is rather shitty, because the hash input is a bit of a random
  // concatenation of stuff, rather than a proper struct.
  var head = struct(
    'K', 'mpint',
    'H', tspt._kex.hash.length
  ).write(null, {
    'K': tspt._kex.secret,
    'H': tspt._kex.hash
  });

  var hash, digest;

  // Create the initial key.
  hash = crypto.createHash(tspt._kex.hashAlgo);
  hash.update(head);
  hash.update(x);
  hash.update(tspt._sessionId);
  digest = hash.digest('binary');
  walk.write(digest, digest.length, 'binary');

  // Create further keys.
  while (walk.pos < amount) {
    hash = crypto.createHash(tspt._kex.hashAlgo);
    hash.update(head);
    hash.update(out.slice(0, walk.pos));
    digest = hash.digest('binary');
    walk.write(digest, digest.length, 'binary');
  }

  return out.toString('binary');
};


// Initiate a key exchange.
var kex = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kex.bind(this, tspt));
  }

  // Send our kexinit.
  init(tspt, writer);

  // FIXME: Send a guess packet
};

// Called to send our kexinit.
var init = function(tspt, writer) {
  // State struct.
  tspt._kex = {
    // Kexinit payloads are stored, for use in the exchange hash.
    clientPayload: null,
    serverPayload: null,

    // Filled by the kex exchange method.
    secret: null,
    hash: null,
    hashAlgo: null,

    // FIXME: better way to handle this circular dep.
    finish: kex.finish
  };

  // FIXME
  var params, payload;
  payload = writer('kexinit', params = {
    cookie: crypto.randomBytes(16),
    kexAlgo: [ 'diffie-hellman-group14-sha1' ],
    keyAlgo: [ 'ssh-dss' ],
    encAlgoClient: [ 'aes128-cbc' ],
    encAlgoServer: [ 'aes128-cbc' ],
    macAlgoClient: [ 'hmac-sha1' ],
    macAlgoServer: [ 'hmac-sha1' ],
    compAlgoClient: [ 'none' ],
    compAlgoServer: [ 'none' ],
    langClient: [],
    langServer: [],
    firstPacketFollows: false
  });

  // Store parameters, and the payload (used in the exchange hash).
  tspt._kex[tspt.role + 'Params']  = params;
  tspt._kex[tspt.role + 'Payload'] = payload;
};

// Peer initiated or responded to a key exchange.
messages.kexinit.handle = function(tspt, params, payload) {
  // Not allowed during another key exchange.
  if (tspt._kex && tspt._kex[tspt._theirRole + 'Params']) {
    // FIXME: bail
    return;
  }

  // Store parameters, and the payload (used in the exchange hash).
  tspt._kex[tspt._theirRole + 'Params']  = params;
  tspt._kex[tspt._theirRole + 'Payload'] = payload;

  tspt.write(function(writer) {
    // They initiated, send our kexinit.
    if (!tspt._kex) {
      init(tspt, writer);
    }

    // FIXME: select method.

    // Start the key exchange.
    kexdh(tspt, writer);
  });
};

// We've got a secret and exchange hash, apply the new keys.
kex.finish = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kex.finish.bind(this, tspt));
  }

  // The first exchange hash is also the session ID.
  var first = !tspt._sessionId;
  if (first) {
    tspt._sessionId = tspt._kex.hash;
  }

  // Setup the receive parameters.
  // FIXME: handle failure
  var xes = (tspt.role === 'client' ? 'ACE' : 'BDF');
  var tx = {
    blockSize: 16,
    cipher: crypto.createCipheriv('AES-128-CBC',
      buildKeyData(tspt, xes[1], 16),
      buildKeyData(tspt, xes[0], 16)
    ),
    macAlgo: 'SHA1',
    macSize: 20,
    macKey: buildKeyData(tspt, xes[2], 20)
  };
  tx.cipher.setAutoPadding(false);

  writer('newkeys');
  tspt._tx = tx;

  // Expect a newkeys in the future, but the protocol can continue.
  tspt.emit('kexComplete', writer);
  if (first) {
    tspt.emit('secure', writer);
  }
};

// Peer has applied the new keys.
messages.newkeys.handle = function(tspt) {
  // We should have a secret and exchange hash at this point.
  if (!tspt._kex || !tspt._kex.secret || !tspt._kex.hash) {
    // FIXME: bail
    return;
  }

  // Setup the receive parameters.
  // FIXME: handle failure
  var xes = (tspt._theirRole === 'client' ? 'ACE' : 'BDF');
  tspt._rx = {
    blockSize: 16,
    cipher: crypto.createDecipheriv('AES-128-CBC',
      buildKeyData(tspt, xes[1], 16),
      buildKeyData(tspt, xes[0], 16)
    ),
    macAlgo: 'SHA1',
    macSize: 20,
    macKey: buildKeyData(tspt, xes[2], 20)
  };
  tspt._rx.cipher.setAutoPadding(false);

  // The key exchange is complete.
  tspt._kex = null;
};


module.exports = kex;
