var net = require('net');
var Transport = require('./lib/transport');
var kex = require('./lib/kex');

exports.version = require('./package.json').version;

exports.connect = function(host, options) {
  options = (options || {});

  var stream = net.connect(options.port || 22, host);
  var tspt = new Transport('client', stream);

  stream.on('connect', function() {
    tspt.write(function(writer) {
      writer('handshake', 'SSH-2.0-sshiny_' + exports.version);
      kex(tspt, writer);
    });
  });

  tspt.on('secure', function(writer) {
    // FIXME: test
    writer('ignore');
  });

  return tspt;
};
