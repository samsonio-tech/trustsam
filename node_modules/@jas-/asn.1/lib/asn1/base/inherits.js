'use strict';

// Links `ctor.prototype` to `superCtor.prototype` with Object.setPrototypeOf,
// so methods already on `ctor.prototype` are kept and `constructor` stays
// correct. Unlike the npm shim, invalid arguments throw instead of being
// silently ignored.

function inherits(ctor, superCtor) {
  if (typeof ctor !== 'function')
    throw new TypeError('inherits: ctor must be a function');
  if (typeof superCtor !== 'function')
    throw new TypeError('inherits: superCtor must be a function');
  if (superCtor.prototype === null || typeof superCtor.prototype !== 'object')
    throw new TypeError('inherits: superCtor.prototype must be an object');

  Object.defineProperty(ctor, 'super_', {
    value: superCtor,
    enumerable: false,
    writable: true,
    configurable: true
  });
  Object.setPrototypeOf(ctor.prototype, superCtor.prototype);
}

module.exports = inherits;
