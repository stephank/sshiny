var struct = require('../struct');


// Build and index transport messages.
var msg = function(name, id) {
  var fields = Array.prototype.slice.call(arguments, 2);

  var def = struct.msg(id, fields);
  def.name = name;

  exports[name] = def;
  exports[id] = def;
};


// As defined in RFC 4253.

// 7. Key Exchange

msg('kexinit', 20,
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
);

msg('newkeys', 21);

// 8. Diffie-Hellman Key Exchange

msg('kexdhinit', 30,
  'e', 'mpint'
);

msg('kexdhreply', 31,
  'publicKey', 'bstring',
  'f', 'mpint',
  'signature', 'bstring'
);

// 10. Service Request

msg('serviceRequest', 5,
  'name', 'string'
);

msg('serviceAccept', 6,
  'name', 'string'
);

// 11. Additional Messages

msg('disconnect', 1,
  'code', 'uint32',
  'description', 'string',
  'language', 'string'
);

msg('ignore', 2);

msg('unimplemented', 3,
  'seq', 'uint32'
);

msg('debug', 4,
  'alwaysDisplay', 'boolean',
  'message', 'string',
  'language', 'string'
);
