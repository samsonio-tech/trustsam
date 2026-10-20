'use strict';

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

assert.equal = function assertEqual(l, r, msg) {
  // Loose equality matches minimalistic-assert.
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};

module.exports = assert;
