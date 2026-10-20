'use strict';

// Implements the bn.js API surface used by this library and its typical
// consumers (construction from numbers/strings/bytes, toString/toJSON,
// toArray/toArrayLike/toBuffer, comparisons and basic arithmetic).
//
// Differences from bn.js, all in the direction of failing loudly:
//   * instances are immutable (frozen); there are no in-place `i*` methods
//   * non-integer or unsafe numbers throw instead of being truncated
//   * plain arrays must contain bytes (0..255)
//   * 'le' endianness is only accepted for byte input

const inspect = require('util').inspect;
const isUint8Array = require('util').types.isUint8Array;
const NativeBuffer = require('buffer').Buffer;
const SafeBuffer = require('./safe-buffer').Buffer;

const BRAND = Symbol.for('asn1.js/bignum');
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

const FAST_BASES = {
  2: { re: /^[01]+$/, prefix: '0b' },
  8: { re: /^[0-7]+$/, prefix: '0o' },
  10: { re: /^[0-9]+$/, prefix: '' },
  16: { re: /^[0-9a-fA-F]+$/, prefix: '0x' }
};

function normalizeBase(base) {
  if (base === undefined || base === null)
    return 10;
  if (base === 'hex')
    return 16;
  if (!Number.isInteger(base) || base < 2 || base > 36)
    throw new RangeError('Invalid base: ' + base);
  return base;
}

function normalizeEndian(endian) {
  if (endian === undefined || endian === null)
    return 'be';
  if (endian !== 'be' && endian !== 'le')
    throw new TypeError('Invalid endianness: ' + endian);
  return endian;
}

function abs(v) {
  return v < 0n ? -v : v;
}

function parseString(str, base) {
  str = str.replace(/\s+/g, '');

  let negative = false;
  if (str[0] === '-') {
    negative = true;
    str = str.slice(1);
  }
  if (str.length === 0)
    return 0n;

  let mag;
  const fast = FAST_BASES[base];
  if (fast) {
    if (!fast.re.test(str))
      throw new Error('Invalid character in ' + str);
    mag = BigInt(fast.prefix + str);
  } else {
    const b = BigInt(base);
    mag = 0n;
    for (let i = 0; i < str.length; i++) {
      const d = parseInt(str[i], 36);
      if (Number.isNaN(d) || d >= base)
        throw new Error('Invalid character in ' + str);
      mag = mag * b + BigInt(d);
    }
  }
  return negative ? -mag : mag;
}

// Copies the input; for plain arrays safe-buffer validates every element.
function parseBytes(bytes, endian) {
  const buf = SafeBuffer.from(bytes);
  if (endian === 'le')
    buf.reverse();
  if (buf.length === 0)
    return 0n;
  return BigInt('0x' + buf.toString('hex'));
}

function toValue(number, base, endian) {
  if (number === undefined || number === null)
    return 0n;

  if (typeof number === 'bigint') {
    if (endian === 'le')
      throw new TypeError('Little-endian is only supported for byte input');
    return number;
  }

  if (typeof number === 'number') {
    if (!Number.isSafeInteger(number))
      throw new RangeError('Number must be a safe integer, got: ' + number);
    if (endian === 'le')
      throw new TypeError('Little-endian is only supported for byte input');
    return BigInt(number);
  }

  if (typeof number === 'string') {
    if (endian === 'le')
      throw new TypeError('Little-endian is only supported for byte input');
    return parseString(number, normalizeBase(base));
  }

  if (Array.isArray(number) || isUint8Array(number))
    return parseBytes(number, endian);

  throw new TypeError('Unsupported bignum input: ' +
                      Object.prototype.toString.call(number));
}

// Coerce an operand for comparisons/arithmetic.
function operand(x) {
  if (BigNum.isBN(x))
    return x._value;
  if (typeof x === 'bigint')
    return x;
  if (typeof x === 'number' && Number.isSafeInteger(x))
    return BigInt(x);
  throw new TypeError('Invalid bignum operand: ' + x);
}

function BigNum(number, base, endian) {
  // Instances are immutable, so returning the same one is safe.
  if (BigNum.isBN(number))
    return number;
  if (!(this instanceof BigNum))
    return new BigNum(number, base, endian);

  if (base === 'le' || base === 'be') {
    endian = base;
    base = 10;
  }

  const value = toValue(number, base, normalizeEndian(endian));
  this._value = value;
  this.negative = value < 0n ? 1 : 0;
  Object.defineProperty(this, BRAND, { value: true });
  Object.freeze(this);
}
module.exports = BigNum;

BigNum.BN = BigNum;

BigNum.isBN = function isBN(num) {
  return num !== null && typeof num === 'object' && num[BRAND] === true;
};

BigNum.max = function max(left, right) {
  return left.cmp(right) > 0 ? left : right;
};

BigNum.min = function min(left, right) {
  return left.cmp(right) < 0 ? left : right;
};

// Conversion

BigNum.prototype.toString = function toString(base, padding) {
  base = normalizeBase(base);
  padding = (padding | 0) || 1;

  let out = abs(this._value).toString(base);
  const rem = out.length % padding;
  if (rem !== 0)
    out = out.padStart(out.length + padding - rem, '0');

  return (this._value < 0n ? '-' : '') + out;
};

BigNum.prototype.toJSON = function toJSON() {
  return this.toString(16, 2);
};

BigNum.prototype.toBigInt = function toBigInt() {
  return this._value;
};

BigNum.prototype.toNumber = function toNumber() {
  if (abs(this._value) > MAX_SAFE)
    throw new RangeError('Number can only safely store up to 53 bits');
  return Number(this._value);
};

BigNum.prototype.bitLength = function bitLength() {
  if (this._value === 0n)
    return 0;
  const hex = abs(this._value).toString(16);
  return (hex.length - 1) * 4 + (32 - Math.clz32(parseInt(hex[0], 16)));
};

BigNum.prototype.byteLength = function byteLength() {
  return Math.ceil(this.bitLength() / 8);
};

// Magnitude only, as in bn.js.
BigNum.prototype.toArrayLike = function toArrayLike(ArrayType, endian,
  length) {
  endian = normalizeEndian(endian);

  const byteLen = this.byteLength();
  const reqLength = length || Math.max(1, byteLen);
  if (!Number.isSafeInteger(reqLength) || reqLength <= 0)
    throw new RangeError('Requested array length <= 0');
  if (byteLen > reqLength)
    throw new RangeError('byte array longer than desired length');

  let out;
  if (ArrayType === Array)
    out = new Array(reqLength).fill(0);
  else if (ArrayType === NativeBuffer || ArrayType === SafeBuffer)
    out = SafeBuffer.alloc(reqLength);
  else if (ArrayType === Uint8Array || ArrayType === Uint8ClampedArray)
    out = new ArrayType(reqLength);
  else
    throw new TypeError('Unsupported array type');

  if (byteLen === 0)
    return out;

  let hex = abs(this._value).toString(16);
  if (hex.length & 1)
    hex = '0' + hex;
  const bytes = SafeBuffer.from(hex, 'hex');

  if (endian === 'be') {
    const off = reqLength - bytes.length;
    for (let i = 0; i < bytes.length; i++)
      out[off + i] = bytes[i];
  } else {
    for (let i = 0; i < bytes.length; i++)
      out[i] = bytes[bytes.length - 1 - i];
  }
  return out;
};

BigNum.prototype.toArray = function toArray(endian, length) {
  return this.toArrayLike(Array, endian, length);
};

BigNum.prototype.toBuffer = function toBuffer(endian, length) {
  return this.toArrayLike(NativeBuffer, endian, length);
};

BigNum.prototype[inspect.custom] = function() {
  return '<BN: ' + this.toString(16) + '>';
};

// Predicates and comparison

BigNum.prototype.isZero = function isZero() {
  return this._value === 0n;
};

BigNum.prototype.isNeg = function isNeg() {
  return this._value < 0n;
};

BigNum.prototype.isOdd = function isOdd() {
  return (this._value & 1n) === 1n;
};

BigNum.prototype.isEven = function isEven() {
  return (this._value & 1n) === 0n;
};

BigNum.prototype.cmp = function cmp(other) {
  const o = operand(other);
  if (this._value < o)
    return -1;
  return this._value > o ? 1 : 0;
};

BigNum.prototype.eq = function eq(other) {
  return this.cmp(other) === 0;
};

BigNum.prototype.lt = function lt(other) {
  return this.cmp(other) < 0;
};

BigNum.prototype.lte = function lte(other) {
  return this.cmp(other) <= 0;
};

BigNum.prototype.gt = function gt(other) {
  return this.cmp(other) > 0;
};

BigNum.prototype.gte = function gte(other) {
  return this.cmp(other) >= 0;
};

// Arithmetic (always returns a new instance)

BigNum.prototype.clone = function clone() {
  return new BigNum(this._value);
};

BigNum.prototype.neg = function neg() {
  return new BigNum(-this._value);
};

BigNum.prototype.abs = function absolute() {
  return new BigNum(abs(this._value));
};

BigNum.prototype.add = function add(other) {
  return new BigNum(this._value + operand(other));
};

BigNum.prototype.sub = function sub(other) {
  return new BigNum(this._value - operand(other));
};

BigNum.prototype.mul = function mul(other) {
  return new BigNum(this._value * operand(other));
};

// Truncates toward zero; division by zero throws RangeError.
BigNum.prototype.div = function div(other) {
  return new BigNum(this._value / operand(other));
};

// Result has the sign of the dividend.
BigNum.prototype.mod = function mod(other) {
  return new BigNum(this._value % operand(other));
};

// Always non-negative.
BigNum.prototype.umod = function umod(other) {
  const m = abs(operand(other));
  const r = this._value % m;
  return new BigNum(r < 0n ? r + m : r);
};
