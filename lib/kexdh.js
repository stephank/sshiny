var crypto = require('crypto');
var messages = require('./messages');

// Initiate a Diffie-Hellman key exchange.
var kexdh = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kexdh.bind(this, tspt));
  }

  tspt._kexdh = {
    dh: crypto.getDiffieHellman('modp14'),
    clientKey: null,
    serverKey: null,
    hostKey: null
  };

  if (tspt.role === 'client') {
    tspt._kexdh.clientKey = tspt._kexdh.dh.generateKeys();
    writer('kexdhinit', { e: tspt._kexdh.clientKey });
  }
};

// Abort the exchange, used when this was a guessed method.
kexdh.clear = function(tspt) {
  tspt._kexdh = null;
};

// The hashing input that'll result in the exchange hash.
var hashDef = messages.createStructDef(
  'V_C', 'string',    // Client identification string.
  'V_S', 'string',    // Server identification string.
  'I_C', 'bstring',   // Client kexinit payload.
  'I_S', 'bstring',   // Server kexinit payload.
  'K_S', 'string',    // Server host key.
  'e', 'mpint',       // Client DH public key.
  'f', 'mpint',       // Server DH public key.
  'K', 'mpint'        // DH shared secret.
);

// Called when all parameters have been collected to create the exchange hash.
buildHash = function(tspt) {
  var input = hashDef.create({
    'V_C': tspt._clientIdent,
    'V_S': tspt._serverIdent,
    'I_C': tspt._kex.clientPayload,
    'I_S': tspt._kex.serverPayload,
    'K_S': tspt._kexdh.hostKey,
    'e': tspt._kexdh.clientKey,
    'f': tspt._kexdh.serverKey,
    'K': tspt._kex.secret
  });

  var hash = crypto.createHash('sha1');
  hash.update(input);
  tspt._kex.hash = hash.digest();
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

    tspt._kexdh.clientKey = params.e;
    tspt._kexdh.serverKey = tspt._kexdh.dh.generateKeys();
    tspt._kex.secret = tspt._kexdh.dh.computeSecret(params.e);
    buildHash(tspt);

    tspt.write(function(writer) {
      writer('kexdhreply', {
        publicKey: '',  // FIXME
        f: tspt._kexdh.serverKey,
        signature: ''   // FIXME
      });

      tspt._kex.finish(tspt, writer);
    });
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

    // FIXME: verify server key

    tspt._kexdh.serverKey = params.f;
    tspt._kexdh.hostKey = params.publicKey;
    tspt._kex.secret = tspt._kexdh.dh.computeSecret(params.f);
    buildHash(tspt);

    tspt._kex.finish(tspt);
  }
});

module.exports = kexdh;
