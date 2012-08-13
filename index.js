var net = require('net');
var Transport = require('./lib/transport');

exports.version = require('./package.json').version;

exports.connect = function(host, options) {
  options = (options || {});

  var stream = net.connect(options.port || 22, host);
  var tspt = new Transport('client', stream);

  stream.on('connect', function() {
    tspt._start(function(writer) {
      // FIXME: test
      writer('ignore');
    });
  });

  return tspt;
};

exports.createServer = function(options) {
  options = (options || {});

  return net.createServer(function(stream) {
    var tspt = new Transport('server', stream);
    tspt._start(function(writer) {
      // FIXME: test
      writer('ignore');
    });
  });
};
