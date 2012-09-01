var crypto = require('crypto');
var struct = require('../../struct');
var M = require('./messages');


var hashInput = struct(
  'V_C', 'string',
  'V_S', 'string',
  'I_C', 'bstring',
  'I_S', 'bstring',
  'K_S', 'bstring',
  'e', 'mpint',
  'f', 'mpint',
  'K', 'mpint'
);

// Called when all parameters have been collected to create the exchange hash.
var buildHash = function(tspt) {
  var state = tspt._kexMethod;
  var kexState = tspt._kex;

  var input = hashInput.write(null, {
    'V_C': tspt._clientIdent,
    'V_S': tspt._serverIdent,
    'I_C': kexState.clientPayload,
    'I_S': kexState.serverPayload,
    'K_S': state.hostKey,
    'e': state.clientKey,
    'f': state.serverKey,
    'K': kexState.secret
  });

  var hash = crypto.createHash(kexState.hashAlgo);
  hash.update(input);
  kexState.hash = hash.digest();
};


// Initiate a Diffie-Hellman key exchange.
var kexdh = function(tspt, writer) {
  if (!writer) {
    return tspt.write(kexdh.bind(this, tspt));
  }

  // State struct.
  var state = tspt._kexMethod = {
    dh: crypto.getDiffieHellman('modp14'),
    clientKey: null,
    serverKey: null,
    hostKey: null,
    handle: M.dispatch
  };

  // DH uses SHA-1.
  tspt._kex.hashAlgo = 'SHA1';

  // If we're the client, we send the first packet.
  if (tspt.role === 'client') {
    state.clientKey = state.dh.generateKeys();
    writer(M.kexdhinit, { e: state.clientKey });
  }

  // FIXME
  if (tspt.role === 'server') {
    state.hostKey = '';
  }
};

// Abort the exchange, used when this was a guessed method.
kexdh.clear = function(tspt) {
  tspt._kexMethod = null;
};

// Client public key packet.
M.kexdhinit.handle = function(tspt, params) {
  var state = tspt._kexMethod;
  var kexState = tspt._kex;

  // Only allowed within a DH key exchange.
  if (!state) {
    // FIXME: bail
    return;
  }

  // Only the client can send this.
  if (tspt.role !== 'server') {
    // FIXME: bail
    return;
  }

  // The server now has all the info it needs.
  var dh = state.dh;
  state.clientKey = params.e;
  state.serverKey = dh.generateKeys();
  kexState.secret = dh.computeSecret(params.e);
  buildHash(tspt);

  tspt.write(function(writer) {
    // Send reply.
    writer(M.kexdhreply, {
      publicKey: '',  // FIXME
      f: state.serverKey,
      signature: ''   // FIXME
    });

    // The DH key exchange is complete.
    tspt._kexMethod = null;

    // Apply the new keys.
    kexState.finish(tspt, writer);
  });
};

// Server public key and auth packet.
M.kexdhreply.handle = function(tspt, params) {
  var state = tspt._kexMethod;
  var kexState = tspt._kex;

  // Only allowed within a DH kex.
  if (!tspt._kexMethod) {
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
  state.serverKey = params.f;
  state.hostKey = params.publicKey;
  kexState.secret = state.dh.computeSecret(params.f);
  buildHash(tspt);

  // The DH key exchange is complete.
  tspt._kexMethod = null;

  // Apply the new keys.
  kexState.finish(tspt);
};


module.exports = kexdh;
