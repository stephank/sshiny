var struct = require('../../struct');

var msg = struct.msgModule(exports);


// 8. Diffie-Hellman Key Exchange

msg('kexdhinit', 30,
  'e', 'mpint'
);

msg('kexdhreply', 31,
  'publicKey', 'bstring',
  'f', 'mpint',
  'signature', 'bstring'
);
