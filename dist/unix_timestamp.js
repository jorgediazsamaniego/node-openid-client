"use strict";

module.exports = function () {
  return Date.now() / 1000 | 0;
}; // eslint-disable-line no-bitwise