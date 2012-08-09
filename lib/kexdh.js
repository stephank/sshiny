var crypto = require('crypto');
var messages = require('./messages');

// Initiate a Diffie-Hellman key exchange.
var kexdh = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kexdh.bind(this, tspt));
  }

  tspt._kexdh = {
    dh: crypto.getDiffieHellman('modp14')
  };

  if (tspt.role === 'client') {
    writer('kexdhinit', {
      e: tspt._kexdh.dh.generateKeys()
    });
  }
};

// Abort the exchange, used when this was a guessed method.
kexdh.clear = function(tspt) {
  tspt._kexdh = null;
};

// Client public key packet.
messages.register({
  name: 'kexdhinit',
  id: 30,

  fields: [
    'e', 'mpint'
  ],

  handle: function(tspt, params) {
    if (!tspt._kexdh) {
      // FIXME: bail
      return;
    }

    if (tspt.role !== 'server') {
      // FIXME: bail
      return;
    }

    // FIXME
  }
});

// Server public key and auth packet.
messages.register({
  name: 'kexdhreply',
  id: 31,

  fields: [
    'publicKey', 'string',
    'f', 'mpint',
    'signature', 'string'
  ],

  handle: function(tspt, params) {
    if (!tspt._kexdh) {
      // FIXME: bail
      return;
    }

    if (tspt.role !== 'client') {
      // FIXME: bail
      return;
    }

    tspt._kexdh.secret = tspt._kexdh.dh.computeSecret(params.f);

    // FIXME: apply write keys, send newkeys
  }
});

// Peer has applied the new keys.
kexdh.finish = function(tspt) {
  // FIXME: apply read keys
};

module.exports = kexdh;
