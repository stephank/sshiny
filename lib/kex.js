var crypto = require('crypto');
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


// Initiate a key exchange.
var kex = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kex.bind(this, tspt));
  }

  // Send our kexinit.
  init(tspt, writer);

  // FIXME: Send a guess packet
};

// Call to send our kexinit.
var init = function(tspt, writer) {
  tspt._kex = {
    clientPayload: null,
    serverPayload: null,
    secret: null,
    hash: null,
    finish: kex.finish // FIXME: better way to handle this circular dep.
  };

  // FIXME
  var params = {
    cookie: crypto.randomBytes(16),
    kexAlgo: [ 'diffie-hellman-group14-sha1' ],
    keyAlgo: [ 'ssh-dss' ],
    encAlgoClient: [ '3des-cbc' ],
    encAlgoServer: [ '3des-cbc' ],
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

// Peer has applied the new keys.
newkeys.handle = function(tspt) {
  // We should have a secret and exchange at this point.
  if (!tspt._kex || !tspt._kex.secret || !tspt._kex.hash) {
    // FIXME: bail
    return;
  }

  // FIXME
};

// We've got a secret and exchange hash, apply the new keys.
kex.finish = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kex.finish.bind(this, tspt));
  }

  writer('newkeys');
};


module.exports = kex;
