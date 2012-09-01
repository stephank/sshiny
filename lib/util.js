// Dump the buffer as hexadecimals, with `perRow` and `perColumn` specified in
// bytes. Optionally a list of `offsets` can be specified, which will insert
// ANSI escape sequences to alter colouring per field.
exports.dumpHex = function(buf, perRow, perColumn, offsets) {
  // Allow a binary string.
  if (typeof(buf) === 'string') {
    buf = new Buffer(buf, 'binary');
  }

  // Convert to hex.
  var hex = buf.toString('hex');
  perRow *= 2;
  perColumn *= 2;

  // Iterate rows.
  var hi = false;
  var lines = [];
  for (var i = 0; i < hex.length; i += perRow) {
    var slice = hex.slice(i, i + perRow);

    // Iterate columns.
    var line = '';
    for (var j = 0; j < slice.length; j += 2) {

      // Check column end.
      if (j !== 0 && (j % perColumn) === 0) {
        line += ' ';
      }

      // Check field end.
      if (offsets) {
        var pos = (i + j) / 2;
        if (offsets.indexOf(pos) !== -1) {
          hi = !hi;
          if (hi) {
            line += '\033[7m';
          }
          else {
            line += '\033[27m';
          }
        }
      }

      // Add the byte.
      line += slice.slice(j, j + 2);

    }
    // Collect the line.
    lines.push(line);
  }

  // Join lines and reset highlighting.
  var text = lines.join('\n');
  if (hi) {
    text += '\033[22m';
  }

  return text;
};
