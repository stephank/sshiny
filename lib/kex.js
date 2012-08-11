var crypto = require('crypto');
var WalkBuf = require('walkbuf');
var messages = require('./messages');
var kexdh = require('./kexdh');


// As defined in RFC 4253, section 7: “Key Exchange”

var kexinit = messages.register({
  name: 'kexinit',
  id: 20,
  fields: [
    'cookie', 16,
    'kexAlgo', 'name-list',
    'keyAlgo', 'name-list',
    'encAlgoClient', 'name-list',
    'encAlgoServer', 'name-list',
    'macAlgoClient', 'name-list',
    'macAlgoServer', 'name-list',
    'compAlgoClient', 'name-list',
    'compAlgoServer', 'name-list',
    'langClient', 'name-list',
    'langServer', 'name-list',
    'firstPacketFollows', 'boolean',
    '!skip', 4
  ]
});

var newkeys = messages.register({
  name: 'newkeys',
  id: 21,
  fields: []
});


// Build data used as keys for the encryption and authentication algorithms.
var buildKeyData = function(tspt, x, amount) {
  var out = new Buffer(amount);
  var walk = new WalkBuf(out);

  // This is a rather shitty, because the hash input is a bit of a random
  // concatenation of stuff, rather than a proper struct.
  var head = messages.createStructDef(
    'K', 'mpint',
    'H', tspt._kex.hash.length
  ).create({
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

  return out;
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
  var params = {
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
  };

  writer('kexinit', params, function(payload) {
    // Store parameters, and the payload (used in the exchange hash).
    tspt._kex[tspt.role + 'Params']  = params;
    tspt._kex[tspt.role + 'Payload'] = payload;
  });
};

// Peer initiated or responded to a key exchange.
kexinit.handle = function(tspt, params, payload) {
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

  // Build cipher and HMAC key data.
  var xes = (tspt.role === 'client' ? 'ACE' : 'BDF');
  var cipher = crypto.createCipher('aes128',
    buildKeyData(tspt, xes[0], 16),
    buildKeyData(tspt, xes[1], 16)
  );
  var authAlgo = 'sha1';
  var authKey = buildKeyData(tspt, xes[2], 20);
  // FIXME: test
  var hmac = crypto.createHmac(authAlgo, authKey);

  writer('newkeys');
  // FIXME: apply

  // Expect a newkeys in the future, but the protocol can continue.
  tspt.emit('kexComplete', writer);
  if (first) {
    tspt.emit('secure', writer);
  }
};

// Peer has applied the new keys.
newkeys.handle = function(tspt) {
  // We should have a secret and exchange hash at this point.
  if (!tspt._kex || !tspt._kex.secret || !tspt._kex.hash) {
    // FIXME: bail
    return;
  }

  // Build cipher and HMAC key data.
  var xes = (tspt._theirRole === 'client' ? 'ACE' : 'BDF');
  var cipher = crypto.createCipher('aes128',
    buildKeyData(tspt, xes[0], 16),
    buildKeyData(tspt, xes[1], 16)
  );
  var authAlgo = 'sha1';
  var authKey = buildKeyData(tspt, xes[2], 20);
  // FIXME: test
  var hmac = crypto.createHmac(authAlgo, authKey);

  // FIXME: apply

  // The key exchange is complete.
  tspt._kex = null;
};


module.exports = kex;
