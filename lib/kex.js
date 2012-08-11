var crypto = require('crypto');
var messages = require('./messages');
var kexdh = require('./kexdh');

// Initiate a key exchange.
var kex = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kex.bind(this, tspt));
  }

  tspt._kex = {};

  sendInit(tspt, writer);
  // FIXME: Send a guess packet
};

// Helper function that writes the kexinit packet.
var sendInit = function(tspt, writer) {
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
    tspt._kex[tspt.role + 'Params']  = params;
    tspt._kex[tspt.role + 'Payload'] = payload;
  });
};

// Message that starts the key exchange.
messages.register({
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
  ],

  // Peer initiated or responded to a key exchange.
  handle: function(tspt, params, payload) {

    if (tspt._kex && tspt._kex[tspt._theirRole + 'Params']) {
      // FIXME: bail
      return;
    }

    tspt.write(function(writer) {
      if (!tspt._kex) {
        tspt._kex = {};
        sendInit(tspt, writer);
      }

      tspt._kex[tspt._theirRole + 'Params']  = params;
      tspt._kex[tspt._theirRole + 'Payload'] = payload;

      // FIXME: select method.
      kexdh(tspt, writer);
    });
  }
});

// Peer has applied the new keys.
messages.register({
  name: 'newkeys',
  id: 21,

  fields: [],

  handle: function(tspt) {
    // FIXME: signal correct algorithm
    kexdh.finish(tspt);
  }
});

module.exports = kex;
