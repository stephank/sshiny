var crypto = require('crypto');
var WalkBuf = require('walkbuf');
var struct = require('../struct');
var kexdh = require('./kexdh');
var M = require('./messages');


// Build data used as keys for the encryption and authentication algorithms.
var buildKeyData = function(tspt, x, amount) {
  var state = tspt._kex;
  var out = new Buffer(amount);
  var walk = new WalkBuf(out);

  // This is rather shitty, because the hash input is a bit of a random
  // concatenation of stuff, rather than a proper struct.
  var head = struct(
    'K', 'mpint',
    'H', state.hash.length
  ).write(null, {
    'K': state.secret,
    'H': state.hash
  });

  var hash, digest;

  // Create the initial key.
  hash = crypto.createHash(state.hashAlgo);
  hash.update(head);
  hash.update(x);
  hash.update(tspt._sessionId);
  digest = hash.digest('binary');
  walk.write(digest, digest.length, 'binary');

  // Create further keys.
  while (walk.pos < amount) {
    hash = crypto.createHash(state.hashAlgo);
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
  var state = {
    // Kexinit payloads are stored, for use in the exchange hash.
    clientPayload: null,
    serverPayload: null,

    // Filled by the kex exchange method.
    secret: null,
    hash: null,
    hashAlgo: null,

    // Flag set after our newkeys, waiting for peer newkeys.
    complete: false,

    // FIXME: better way to handle this circular dep.
    finish: kex.finish
  };

  // FIXME
  var params, payload;
  writer(M.kexinit, params = {
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
  }, function(payload) {
    // Store parameters, and the payload (used in the exchange hash).
    var role = tspt.role;
    state[role + 'Params']  = params;
    state[role + 'Payload'] = payload;
  });

  tspt._kex = state;
  return state;
};

// Peer initiated or responded to a key exchange.
M.kexinit.handle = function(tspt, params, payload) {
  tspt.write(function(writer) {
    // Not allowed during another key exchange.
    if (kex.isPeerInKex(tspt)) {
      writer.unimplemented();
      return;
    }

    // They initiated, send our kexinit.
    var state = tspt._kex;
    if (!state) {
      state = init(tspt, writer);
    }

    // Store parameters, and the payload (used in the exchange hash).
    var theirRole = tspt._theirRole;
    state[theirRole + 'Params']  = params;
    state[theirRole + 'Payload'] = payload;

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

  var state = tspt._kex;

  // The first exchange hash is also the session ID.
  var first = !tspt._sessionId;
  if (first) {
    tspt._sessionId = state.hash;
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

  // Commit.
  writer(M.newkeys);
  tspt._tx = tx;
  state.complete = true;
  tspt.emit('kexComplete');

  // Expect a newkeys in the future, but the protocol can continue.
  writer._flush();
};

// Peer has applied the new keys.
M.newkeys.handle = function(tspt) {
  var state = tspt._kex;

  // We should have a secret and exchange hash at this point.
  if (!state || !state.secret || !state.hash) {
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


// Helper: Are we in a key exchange?
kex.isInKex = function(tspt) {
  var state = tspt._kex;
  return state && !state.complete;
};

// Helper: Is the peer in a key exchange?
kex.isPeerInKex = function(tspt) {
  var state = tspt._kex;
  return state && state[tspt._theirRole + 'Params'];
};


module.exports = kex;
