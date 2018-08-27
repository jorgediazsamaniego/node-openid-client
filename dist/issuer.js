'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var jose = require('node-jose');
var assert = require('assert');
var util = require('util');
var url = require('url');
var _ = require('lodash');
var LRU = require('lru-cache');

var DEFAULT_HTTP_OPTIONS = require('./consts').DEFAULT_HTTP_OPTIONS;
var ISSUER_DEFAULTS = require('./consts').ISSUER_DEFAULTS;
var DISCOVERY = require('./consts').DISCOVERY;
var WEBFINGER = require('./consts').WEBFINGER;
var REL = require('./consts').REL;

var got = require('./request');
var errorHandler = require('./error_handler');
var BaseClient = require('./client');
var registry = require('./issuer_registry');
var expectResponse = require('./expect_response');
var webfingerNormalize = require('./webfinger_normalize');

var privateProps = new WeakMap();

var defaultHttpOptions = _.clone(DEFAULT_HTTP_OPTIONS);

function instance(ctx) {
  if (!privateProps.has(ctx)) privateProps.set(ctx, { metadata: {} });
  return privateProps.get(ctx);
}

function stripTrailingSlash(uri) {
  if (uri && uri.endsWith('/')) {
    return uri.slice(0, -1);
  }
  return uri;
}

var Issuer = function () {
  /**
   * @name constructor
   * @api public
   */
  function Issuer(metadata) {
    var _this = this;

    _classCallCheck(this, Issuer);

    var properties = Object.assign({}, ISSUER_DEFAULTS, metadata);

    ['introspection', 'revocation'].forEach(function (endpoint) {
      var _$defaults;

      _.defaults(properties, (_$defaults = {}, _defineProperty(_$defaults, endpoint + '_endpoint', properties['token_' + endpoint + '_endpoint']), _defineProperty(_$defaults, endpoint + '_endpoint_auth_methods_supported', properties.token_endpoint_auth_methods_supported), _defineProperty(_$defaults, endpoint + '_endpoint_auth_signing_alg_values_supported', properties.token_endpoint_auth_signing_alg_values_supported), _$defaults));
    });

    _.forEach(properties, function (value, key) {
      instance(_this).metadata[key] = value;
      if (!_this[key]) {
        Object.defineProperty(_this, key, {
          get: function get() {
            return instance(this).metadata[key];
          }
        });
      }
    });

    instance(this).cache = new LRU({ max: 100 });

    registry.set(this.issuer, this);

    var self = this;

    Object.defineProperty(this, 'Client', {
      value: function (_BaseClient) {
        _inherits(Client, _BaseClient);

        function Client() {
          _classCallCheck(this, Client);

          return _possibleConstructorReturn(this, (Client.__proto__ || Object.getPrototypeOf(Client)).apply(this, arguments));
        }

        _createClass(Client, [{
          key: 'issuer',
          get: function get() {
            return this.constructor.issuer;
          }
        }], [{
          key: 'issuer',
          get: function get() {
            return self;
          }
        }]);

        return Client;
      }(BaseClient)
    });
  }

  /**
   * @name inspect
   * @api public
   */


  _createClass(Issuer, [{
    key: 'inspect',
    value: function inspect() {
      return util.format('Issuer <%s>', this.issuer);
    }

    /**
     * @name keystore
     * @api private
     */

  }, {
    key: 'keystore',
    value: function keystore(reload) {
      var _this3 = this;

      if (!this.jwks_uri) return Promise.reject(new Error('jwks_uri must be configured'));

      var keystore = instance(this).keystore;
      var lookupCache = instance(this).cache;

      if (reload || !keystore) {
        lookupCache.reset();
        return got(this.jwks_uri, this.httpOptions()).then(expectResponse(200)).then(function (response) {
          return JSON.parse(response.body);
        }).then(function (jwks) {
          return jose.JWK.asKeyStore(jwks);
        }).then(function (joseKeyStore) {
          lookupCache.set('throttle', true, 60 * 1000);
          instance(_this3).keystore = joseKeyStore;
          return joseKeyStore;
        }).catch(errorHandler);
      }

      return Promise.resolve(keystore);
    }

    /**
     * @name key
     * @api private
     */

  }, {
    key: 'key',
    value: function key(def, allowMulti) {
      var lookupCache = instance(this).cache;

      // refresh keystore on every unknown key but also only upto once every minute
      var freshJwksUri = lookupCache.get(def) || lookupCache.get('throttle');

      return this.keystore(!freshJwksUri).then(function (store) {
        return store.all(def);
      }).then(function (keys) {
        assert(keys.length, 'no valid key found');
        if (!allowMulti) {
          assert.equal(keys.length, 1, 'multiple matching keys, kid must be provided');
          lookupCache.set(def, true);
        }
        return keys[0];
      });
    }

    /**
     * @name metadata
     * @api public
     */

  }, {
    key: 'httpOptions',


    /**
     * @name httpOptions
     * @api public
     */
    value: function httpOptions() {
      return this.constructor.httpOptions.apply(this.constructor, arguments); // eslint-disable-line prefer-rest-params, max-len
    }

    /**
     * @name httpOptions
     * @api public
     */

  }, {
    key: 'metadata',
    get: function get() {
      return instance(this).metadata;
    }

    /**
     * @name webfinger
     * @api public
     */

  }], [{
    key: 'webfinger',
    value: function webfinger(input) {
      var _this4 = this;

      var resource = webfingerNormalize(input);
      var host = url.parse(resource).host;
      var query = { resource: resource, rel: REL };
      var opts = { query: query, followRedirect: true };
      var webfingerUrl = 'https://' + host + WEBFINGER;

      return got(webfingerUrl, this.httpOptions(opts)).then(expectResponse(200)).then(function (response) {
        return JSON.parse(response.body);
      }).then(function (body) {
        var location = _.find(body.links, function (link) {
          return (typeof link === 'undefined' ? 'undefined' : _typeof(link)) === 'object' && link.rel === REL && link.href;
        });
        assert(location, 'no issuer found in webfinger');
        assert(typeof location.href === 'string' && location.href.startsWith('https://'), 'invalid issuer location');
        var expectedIssuer = location.href;
        if (registry.has(expectedIssuer)) return registry.get(expectedIssuer);

        return _this4.discover(expectedIssuer).then(function (issuer) {
          try {
            assert.equal(issuer.issuer, expectedIssuer, 'discovered issuer mismatch');
          } catch (err) {
            registry.delete(issuer.issuer);
            throw err;
          }
          return issuer;
        });
      });
    }

    /**
     * @name discover
     * @api public
     */

  }, {
    key: 'discover',
    value: function discover(uri) {
      var _this5 = this;

      uri = stripTrailingSlash(uri); // eslint-disable-line no-param-reassign
      var isWellKnown = uri.endsWith(DISCOVERY);
      var wellKnownUri = isWellKnown ? uri : '' + uri + DISCOVERY;

      return got(wellKnownUri, this.httpOptions()).then(expectResponse(200)).then(function (response) {
        return new _this5(JSON.parse(response.body));
      }).catch(errorHandler);
    }
  }, {
    key: 'httpOptions',
    value: function httpOptions(values) {
      return _.merge({}, this.defaultHttpOptions, values);
    }

    /**
     * @name defaultHttpOptions
     * @api public
     */

  }, {
    key: 'defaultHttpOptions',
    get: function get() {
      return defaultHttpOptions;
    }

    /**
     * @name defaultHttpOptions=
     * @api public
     */
    ,
    set: function set(value) {
      defaultHttpOptions = _.merge({}, DEFAULT_HTTP_OPTIONS, value);
    }
  }]);

  return Issuer;
}();

module.exports = Issuer;