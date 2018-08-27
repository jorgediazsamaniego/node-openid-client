'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var now = require('./unix_timestamp');
var base64url = require('base64url');

var decodedClaims = new WeakMap();

var TokenSet = function () {
  /**
   * @name constructor
   * @api public
   */
  function TokenSet(values) {
    _classCallCheck(this, TokenSet);

    Object.assign(this, values);
  }

  /**
   * @name expires_in=
   * @api public
   */


  _createClass(TokenSet, [{
    key: 'expired',


    /**
     * @name expired
     * @api public
     */
    value: function expired() {
      return this.expires_in === 0;
    }

    /**
     * @name claims
     * @api public
     */

  }, {
    key: 'expires_in',
    set: function set(value) {
      // eslint-disable-line camelcase
      this.expires_at = now() + Number(value);
    }

    /**
     * @name expires_in
     * @api public
     */
    ,
    get: function get() {
      // eslint-disable-line camelcase
      return Math.max.apply(null, [this.expires_at - now(), 0]);
    }
  }, {
    key: 'claims',
    get: function get() {
      if (decodedClaims.has(this)) return decodedClaims.get(this);
      if (!this.id_token) throw new Error('id_token not present in TokenSet');

      var decoded = JSON.parse(base64url.decode(this.id_token.split('.')[1]));
      decodedClaims.set(this, decoded);
      return decoded;
    }
  }]);

  return TokenSet;
}();

module.exports = TokenSet;