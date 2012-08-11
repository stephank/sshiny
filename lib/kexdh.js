var crypto = require('crypto');
var messages = require('./messages');


// As defined in RFC 4253, section 8: “Diffie-Hellman Key Exchange”

var kexdhinit = messages.register({
  name: 'kexdhinit',
  id: 30,
  fields: [
    'e', 'mpint'
  ]
});

var kexdhreply = messages.register({
  name: 'kexdhreply',
  id: 31,
  fields: [
    'publicKey', 'string',
    'f', 'mpint',
    'signature', 'string'
  ]
});

var hashInput = messages.createStructDef(
  'V_C', 'string',
  'V_S', 'string',
  'I_C', 'bstring',
  'I_S', 'bstring',
  'K_S', 'string',
  'e', 'mpint',
  'f', 'mpint',
  'K', 'mpint'
);


// Called when all parameters have been collected to create the exchange hash.
buildHash = function(tspt) {
  var input = hashInput.create({
    'V_C': tspt._clientIdent,
    'V_S': tspt._serverIdent,
    'I_C': tspt._kex.clientPayload,
    'I_S': tspt._kex.serverPayload,
    'K_S': tspt._kexdh.hostKey,
    'e': tspt._kexdh.clientKey,
    'f': tspt._kexdh.serverKey,
    'K': tspt._kex.secret
  });

  var hash = crypto.createHash(tspt._kex.hashAlgo);
  hash.update(input);
  tspt._kex.hash = hash.digest();
};


// Initiate a Diffie-Hellman key exchange.
var kexdh = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kexdh.bind(this, tspt));
  }

  // State struct.
  tspt._kexdh = {
    dh: crypto.getDiffieHellman('modp14'),
    clientKey: null,
    serverKey: null,
    hostKey: null
  };

  // DH uses SHA-1.
  tspt._kex.hashAlgo = 'sha1';

  // If we're the client, we send the first packet.
  if (tspt.role === 'client') {
    tspt._kexdh.clientKey = tspt._kexdh.dh.generateKeys();
    writer('kexdhinit', { e: tspt._kexdh.clientKey });
  }
};

// Abort the exchange, used when this was a guessed method.
kexdh.clear = function(tspt) {
  tspt._kexdh = null;
};

// Client public key packet.
kexdhinit.handle = function(tspt, params) {
  // Only allowed within a DH key exchange.
  if (!tspt._kexdh) {
    // FIXME: bail
    return;
  }

  // Only the client can send this.
  if (tspt.role !== 'server') {
    // FIXME: bail
    return;
  }

  // The server now has all the info it needs.
  tspt._kexdh.clientKey = params.e;
  tspt._kexdh.serverKey = tspt._kexdh.dh.generateKeys();
  tspt._kex.secret = tspt._kexdh.dh.computeSecret(params.e);
  buildHash(tspt);

  tspt.write(function(writer) {
    // Send reply.
    writer('kexdhreply', {
      publicKey: '',  // FIXME
      f: tspt._kexdh.serverKey,
      signature: ''   // FIXME
    });

    // The DH key exchange is complete.
    tspt._kexdh = null;

    // Apply the new keys.
    tspt._kex.finish(tspt, writer);
  });
};

// Server public key and auth packet.
kexdhreply.handle = function(tspt, params) {
  // Only allowed within a DH kex.
  if (!tspt._kexdh) {
    // FIXME: bail
    return;
  }

  // Only the server can send this.
  if (tspt.role !== 'client') {
    // FIXME: bail
    return;
  }

  // FIXME: verify server key

  // The client now has all the info it needs.
  tspt._kexdh.serverKey = params.f;
  tspt._kexdh.hostKey = params.publicKey;
  tspt._kex.secret = tspt._kexdh.dh.computeSecret(params.f);
  buildHash(tspt);

  // The DH key exchange is complete.
  tspt._kexdh = null;

  // Apply the new keys.
  tspt._kex.finish(tspt);
};


module.exports = kexdh;
