'use strict';

const NativeBuffer = require('buffer').Buffer;
const kMaxLength = require('buffer').constants.MAX_LENGTH;
const isArrayBuffer = require('util').types.isArrayBuffer;

function isBuffer(value) {
  return NativeBuffer.isBuffer(value);
}

function assertSize(size) {
  if (typeof size !== 'number' || !Number.isSafeInteger(size))
    throw new TypeError('Buffer size must be an integer, got: ' + size);
  if (size < 0 || size > kMaxLength)
    throw new RangeError('Buffer size out of range: ' + size);
}

function assertEncoding(encoding) {
  if (encoding !== undefined && !NativeBuffer.isEncoding(encoding))
    throw new TypeError('Unknown encoding: ' + encoding);
}

function alloc(size, fill, encoding) {
  assertSize(size);
  if (fill === undefined)
    return NativeBuffer.alloc(size);

  if (typeof fill === 'string')
    assertEncoding(encoding);
  else if (typeof fill !== 'number' && !(fill instanceof Uint8Array))
    throw new TypeError('Invalid fill value');

  return NativeBuffer.alloc(size, fill, encoding);
}

function from(value, encoding) {
  if (typeof value === 'number')
    throw new TypeError('Buffer.from() does not accept a number, use alloc()');

  if (typeof value === 'string') {
    assertEncoding(encoding);
    return NativeBuffer.from(value, encoding);
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const b = value[i];
      if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 0xff)
        throw new TypeError('Array element ' + i + ' is not a byte: ' + b);
    }
    return NativeBuffer.from(value);
  }

  // Buffer, Uint8Array and other typed array views: copy bytes.
  if (ArrayBuffer.isView(value)) {
    return NativeBuffer.from(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  }

  // Copy instead of sharing the underlying memory.
  if (isArrayBuffer(value))
    return NativeBuffer.from(new Uint8Array(value));

  throw new TypeError('Unsupported Buffer.from() input: ' +
                      Object.prototype.toString.call(value));
}

function byteLength(value, encoding) {
  if (typeof value === 'string')
    assertEncoding(encoding);
  return NativeBuffer.byteLength(value, encoding);
}

exports.Buffer = Object.freeze({
  alloc: alloc,
  from: from,
  isBuffer: isBuffer,
  byteLength: byteLength,
  kMaxLength: kMaxLength
});
