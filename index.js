var net = require('net');
var Transport = require('./lib/transport');
var service = require('./lib/transport/service');

exports.connect = function(host, options) {
  options = (options || {});

  var stream = net.connect(options.port || 22, host);
  var tspt = new Transport('client', stream);

  stream.on('connect', function() {
    tspt._start(function(writer) {
      service(tspt, 'ssh-userauth', writer);
    });
  });

  return tspt;
};

exports.createServer = function(options) {
  options = (options || {});

  return net.createServer(function(stream) {
    var tspt = new Transport('server', stream);
    tspt._start();
  });
};
