'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var util = require('util');
var assert = require('assert');
var http = require('http');
var crypto = require('crypto');
var querystring = require('querystring');
var jose = require('node-jose');
var uuid = require('uuid');
var base64url = require('base64url');
var url = require('url');
var _ = require('lodash');
// const got = require('got');
var got = require('./request');

var tokenHash = require('oidc-token-hash');

var errorHandler = require('./error_handler');
var expectResponse = require('./expect_response');
var TokenSet = require('./token_set');
var OpenIdConnectError = require('./open_id_connect_error');
var now = require('./unix_timestamp');

var CALLBACK_PROPERTIES = require('./consts').CALLBACK_PROPERTIES;
var CLIENT_DEFAULTS = require('./consts').CLIENT_DEFAULTS;
var JWT_CONTENT = require('./consts').JWT_CONTENT;

var issuerRegistry = require('./issuer_registry');

var map = new WeakMap();
var format = 'compact';

function bearer(token) {
  return 'Bearer ' + token;
}

function instance(ctx) {
  if (!map.has(ctx)) map.set(ctx, { metadata: {} });
  return map.get(ctx);
}

function cleanUpClaims(claims) {
  if (_.isEmpty(claims._claim_names)) delete claims._claim_names;
  if (_.isEmpty(claims._claim_sources)) delete claims._claim_sources;
  return claims;
}

function assignClaim(target, source, sourceName) {
  return function (inSource, claim) {
    if (inSource === sourceName) {
      assert(source[claim] !== undefined, 'expected claim "' + claim + '" in "' + sourceName + '"');
      target[claim] = source[claim];
      delete target._claim_names[claim];
    }
  };
}

function getFromJWT(jwt, position, claim) {
  assert.equal(typeof jwt === 'undefined' ? 'undefined' : _typeof(jwt), 'string', 'invalid JWT type, expected a string');
  var parts = jwt.split('.');
  assert.equal(parts.length, 3, 'invalid JWT format, expected three parts');
  var parsed = JSON.parse(base64url.decode(parts[position]));
  return typeof claim === 'undefined' ? parsed : parsed[claim];
}

function getSub(jwt) {
  return getFromJWT(jwt, 1, 'sub');
}

function getIss(jwt) {
  return getFromJWT(jwt, 1, 'iss');
}

function getHeader(jwt) {
  return getFromJWT(jwt, 0);
}

function getPayload(jwt) {
  return getFromJWT(jwt, 1);
}

function assignErrSrc(sourceName) {
  return function (err) {
    err.src = sourceName;
    throw err;
  };
}

function authorizationParams(params) {
  assert.equal(typeof params === 'undefined' ? 'undefined' : _typeof(params), 'object', 'you must provide an object');

  var authParams = _.chain(params).defaults({
    client_id: this.client_id,
    scope: 'openid',
    response_type: 'code'
  }).forEach(function (value, key, object) {
    if (value === null || value === undefined) {
      delete object[key];
    } else if (key === 'claims' && (typeof value === 'undefined' ? 'undefined' : _typeof(value)) === 'object') {
      object[key] = JSON.stringify(value);
    } else if (typeof value !== 'string') {
      object[key] = String(value);
    }
  }).value();

  assert(authParams.response_type === 'code' || authParams.nonce, 'nonce MUST be provided for implicit and hybrid flows');

  return authParams;
}

function claimJWT(jwt) {
  var _this = this;

  try {
    var iss = getIss(jwt);
    var keyDef = getHeader(jwt);
    assert(keyDef.alg, 'claim source is missing JWT header alg property');

    if (keyDef.alg === 'none') return Promise.resolve(getPayload(jwt));

    var getKey = function () {
      if (!iss || iss === _this.issuer.issuer) {
        return _this.issuer.key(keyDef);
      } else if (issuerRegistry.has(iss)) {
        return issuerRegistry.get(iss).key(keyDef);
      }
      return _this.issuer.constructor.discover(iss).then(function (issuer) {
        return issuer.key(keyDef);
      });
    }();

    return getKey.then(function (key) {
      return jose.JWS.createVerify(key).verify(jwt);
    }).then(function (result) {
      return JSON.parse(result.payload);
    });
  } catch (error) {
    return Promise.reject(error);
  }
}

var deprecatedKeystore = util.deprecate(function (keystore) {
  return keystore;
}, 'passing keystore directly is deprecated, pass an object with keystore property instead');

var Client = function () {
  /**
   * @name constructor
   * @api public
   */
  function Client(metadata, keystore) {
    var _this2 = this;

    _classCallCheck(this, Client);

    var properties = Object.assign({}, CLIENT_DEFAULTS, metadata);

    if (String(properties.token_endpoint_auth_method).endsWith('_jwt')) {
      assert(this.issuer.token_endpoint_auth_signing_alg_values_supported, 'token_endpoint_auth_signing_alg_values_supported must be provided on the issuer');
    }

    ['introspection', 'revocation'].forEach(function (endpoint) {
      var _$defaults;

      _.defaults(properties, (_$defaults = {}, _defineProperty(_$defaults, endpoint + '_endpoint_auth_method', properties.token_endpoint_auth_method), _defineProperty(_$defaults, endpoint + '_endpoint_auth_signing_alg', properties.token_endpoint_auth_signing_alg), _$defaults));
      if (String(properties[endpoint + '_endpoint_auth_method']).endsWith('_jwt')) {
        assert(_this2.issuer[endpoint + '_endpoint_auth_signing_alg_values_supported'], endpoint + '_endpoint_auth_signing_alg_values_supported must be provided on the issuer');
      }
    });

    _.forEach(properties, function (value, key) {
      instance(_this2).metadata[key] = value;
      if (!_this2[key]) {
        Object.defineProperty(_this2, key, {
          get: function get() {
            return instance(this).metadata[key];
          }
        });
      }
    });

    if (keystore !== undefined) {
      assert(jose.JWK.isKeyStore(keystore), 'keystore must be an instance of jose.JWK.KeyStore');
      instance(this).keystore = keystore;
    }

    this.CLOCK_TOLERANCE = 0;
  }

  /**
   * @name authorizationUrl
   * @api public
   */


  _createClass(Client, [{
    key: 'authorizationUrl',
    value: function authorizationUrl(params) {
      assert(this.issuer.authorization_endpoint, 'authorization_endpoint must be configured');
      return url.format(_.defaults({
        search: null,
        query: authorizationParams.call(this, params)
      }, url.parse(this.issuer.authorization_endpoint)));
    }

    /**
     * @name authorizationPost
     * @api public
     */

  }, {
    key: 'authorizationPost',
    value: function authorizationPost(params) {
      var inputs = authorizationParams.call(this, params);
      var formInputs = Object.keys(inputs).map(function (name) {
        return '<input type="hidden" name="' + name + '" value="' + inputs[name] + '"/>';
      }).join('\n');

      return '<!DOCTYPE html>\n<head>\n  <title>Requesting Authorization</title>\n</head>\n<body onload="javascript:document.forms[0].submit()">\n  <form method="post" action="' + this.issuer.authorization_endpoint + '">\n    ' + formInputs + '\n  </form>\n</body>\n</html>';
    }

    /**
     * @name callbackParams
     * @api public
     */

  }, {
    key: 'callbackParams',
    value: function callbackParams(input) {
      // eslint-disable-line
      var isIncomingMessage = input instanceof http.IncomingMessage;
      var isString = typeof input === 'string';

      assert(isString || isIncomingMessage, '#callbackParams only accepts string urls or http.IncomingMessage');

      var uri = void 0;
      if (isIncomingMessage) {
        var msg = input;

        switch (msg.method) {
          case 'GET':
            uri = msg.url;
            break;
          case 'POST':
            assert(msg.body, 'incoming message body missing, include a body parser prior to this call');
            switch (_typeof(msg.body)) {
              case 'object':
              case 'string':
                if (Buffer.isBuffer(msg.body)) {
                  return querystring.parse(msg.body.toString('utf-8'));
                } else if (typeof msg.body === 'string') {
                  return querystring.parse(msg.body);
                }

                return msg.body;
              default:
                throw new Error('invalid IncomingMessage body object');
            }
          default:
            throw new Error('invalid IncomingMessage method');
        }
      } else {
        uri = input;
      }

      return _.pick(url.parse(uri, true).query, CALLBACK_PROPERTIES);
    }

    /**
     * @name authorizationCallback
     * @api public
     */

  }, {
    key: 'authorizationCallback',
    value: function authorizationCallback(redirectUri, parameters, checks) {
      var _this3 = this;

      var params = _.pick(parameters, CALLBACK_PROPERTIES);
      var toCheck = checks || {};

      if (this.default_max_age && !toCheck.max_age) toCheck.max_age = this.default_max_age;

      if (toCheck.state !== parameters.state) {
        return Promise.reject(new Error('state mismatch'));
      }

      if (params.error) {
        return Promise.reject(new OpenIdConnectError(params));
      }

      var promise = void 0;

      if (params.id_token) {
        promise = Promise.resolve(new TokenSet(params)).then(function (tokenset) {
          return _this3.decryptIdToken(tokenset, 'id_token');
        }).then(function (tokenset) {
          return _this3.validateIdToken(tokenset, toCheck.nonce, 'authorization', toCheck.max_age);
        });
      }

      if (params.code) {
        var grantCall = function grantCall() {
          return _this3.grant({
            grant_type: 'authorization_code',
            code: params.code,
            redirect_uri: redirectUri,
            code_verifier: toCheck.code_verifier
          }).then(function (tokenset) {
            return _this3.decryptIdToken(tokenset, 'id_token');
          }).then(function (tokenset) {
            return _this3.validateIdToken(tokenset, toCheck.nonce, 'token', toCheck.max_age);
          }).then(function (tokenset) {
            if (params.session_state) tokenset.session_state = params.session_state;
            return tokenset;
          });
        };

        if (promise) {
          promise = promise.then(grantCall);
        } else {
          return grantCall();
        }
      }

      return promise;
    }

    /**
     * @name oauthCallback
     * @api public
     */

  }, {
    key: 'oauthCallback',
    value: function oauthCallback(redirectUri, parameters, checks) {
      var params = _.pick(parameters, CALLBACK_PROPERTIES);
      var toCheck = checks || {};

      if (toCheck.state !== parameters.state) {
        return Promise.reject(new Error('state mismatch'));
      }

      if (params.error) {
        return Promise.reject(new OpenIdConnectError(params));
      }

      if (params.code) {
        return this.grant({
          grant_type: 'authorization_code',
          code: params.code,
          redirect_uri: redirectUri,
          code_verifier: toCheck.code_verifier
        });
      }

      return Promise.resolve(new TokenSet(params));
    }

    /**
     * @name decryptIdToken
     * @api private
     */

  }, {
    key: 'decryptIdToken',
    value: function decryptIdToken(token, use) {
      if (use === 'userinfo' && !this.userinfo_encrypted_response_alg || use === 'id_token' && !this.id_token_encrypted_response_alg) {
        return Promise.resolve(token);
      }

      var idToken = token;

      if (idToken instanceof TokenSet) {
        assert(idToken.id_token, 'id_token not present in TokenSet');
        idToken = idToken.id_token;
      }

      var expectedAlg = void 0;
      var expectedEnc = void 0;

      if (use === 'userinfo') {
        expectedAlg = this.userinfo_encrypted_response_alg;
        expectedEnc = this.userinfo_encrypted_response_enc;
      } else {
        expectedAlg = this.id_token_encrypted_response_alg;
        expectedEnc = this.id_token_encrypted_response_enc;
      }

      var header = JSON.parse(base64url.decode(idToken.split('.')[0]));

      assert.equal(header.alg, expectedAlg, 'unexpected alg received');
      assert.equal(header.enc, expectedEnc, 'unexpected enc received');

      var keystoreOrSecret = expectedAlg.match(/^(RSA|ECDH)/) ? Promise.resolve(instance(this).keystore) : this.joseSecret(expectedAlg);

      return keystoreOrSecret.then(function (keyOrStore) {
        return jose.JWE.createDecrypt(keyOrStore).decrypt(idToken).then(function (result) {
          if (token instanceof TokenSet) {
            token.id_token = result.payload.toString('utf8');
            return token;
          }
          return result.payload.toString('utf8');
        });
      });
    }

    /**
     * @name validateIdToken
     * @api private
     */

  }, {
    key: 'validateIdToken',
    value: function validateIdToken(tokenSet, nonce, returnedBy, maxAge) {
      var _this4 = this;

      var idToken = tokenSet;

      var expectedAlg = function () {
        if (returnedBy === 'userinfo') return _this4.userinfo_signed_response_alg;
        return _this4.id_token_signed_response_alg;
      }();

      var isTokenSet = idToken instanceof TokenSet;

      if (isTokenSet) {
        assert(idToken.id_token, 'id_token not present in TokenSet');
        idToken = idToken.id_token;
      }

      idToken = String(idToken);

      var timestamp = now();
      var parts = idToken.split('.');
      var header = JSON.parse(base64url.decode(parts[0]));
      var payload = JSON.parse(base64url.decode(parts[1]));

      var verifyPresence = function verifyPresence(prop) {
        if (payload[prop] === undefined) {
          throw new Error('missing required JWT property ' + prop);
        }
      };

      assert.equal(header.alg, expectedAlg, 'unexpected algorithm received');

      if (returnedBy !== 'userinfo') {
        ['iss', 'sub', 'aud', 'exp', 'iat'].forEach(verifyPresence);
      }

      if (payload.iss !== undefined) {
        assert.equal(this.issuer.issuer, payload.iss, 'unexpected iss value');
      }

      if (payload.iat !== undefined) {
        assert.equal(_typeof(payload.iat), 'number', 'iat is not a number');
        assert(payload.iat <= timestamp + this.CLOCK_TOLERANCE, 'id_token issued in the future');
      }

      if (payload.nbf !== undefined) {
        assert.equal(_typeof(payload.nbf), 'number', 'nbf is not a number');
        assert(payload.nbf <= timestamp + this.CLOCK_TOLERANCE, 'id_token not active yet');
      }

      if (maxAge || maxAge !== null && this.require_auth_time) {
        assert(payload.auth_time, 'missing required JWT property auth_time');
        assert.equal(_typeof(payload.auth_time), 'number', 'auth_time is not a number');
      }

      if (maxAge) {
        assert(payload.auth_time + maxAge >= timestamp - this.CLOCK_TOLERANCE, 'too much time has elapsed since the last End-User authentication');
      }

      if (nonce !== null && (payload.nonce || nonce !== undefined)) {
        assert.equal(payload.nonce, nonce, 'nonce mismatch');
      }

      if (payload.exp !== undefined) {
        assert.equal(_typeof(payload.exp), 'number', 'exp is not a number');
        assert(timestamp - this.CLOCK_TOLERANCE < payload.exp, 'id_token expired');
      }

      if (payload.aud !== undefined) {
        if (!Array.isArray(payload.aud)) {
          payload.aud = [payload.aud];
        } else if (payload.aud.length > 1 && !payload.azp) {
          throw new Error('missing required JWT property azp');
        }
      }

      if (payload.azp !== undefined) {
        assert.equal(this.client_id, payload.azp, 'azp must be the client_id');
      }

      if (payload.aud !== undefined) {
        assert(payload.aud.indexOf(this.client_id) !== -1, 'aud is missing the client_id');
      }

      if (returnedBy === 'authorization') {
        assert(payload.at_hash || !tokenSet.access_token, 'missing required property at_hash');
        assert(payload.c_hash || !tokenSet.code, 'missing required property c_hash');
      }

      if (tokenSet.access_token && payload.at_hash !== undefined) {
        assert(tokenHash(payload.at_hash, tokenSet.access_token), 'at_hash mismatch');
      }

      if (tokenSet.code && payload.c_hash !== undefined) {
        assert(tokenHash(payload.c_hash, tokenSet.code), 'c_hash mismatch');
      }

      if (header.alg === 'none') {
        return Promise.resolve(tokenSet);
      }

      return (header.alg.startsWith('HS') ? this.joseSecret() : this.issuer.key(header)).then(function (key) {
        return jose.JWS.createVerify(key).verify(idToken).catch(function () {
          throw new Error('invalid signature');
        });
      }).then(function () {
        return tokenSet;
      });
    }

    /**
     * @name refresh
     * @api public
     */

  }, {
    key: 'refresh',
    value: function refresh(refreshToken) {
      var _this5 = this;

      var token = refreshToken;

      if (token instanceof TokenSet) {
        if (!token.refresh_token) {
          return Promise.reject(new Error('refresh_token not present in TokenSet'));
        }
        token = token.refresh_token;
      }

      return this.grant({
        grant_type: 'refresh_token',
        refresh_token: String(token)
      }).then(function (tokenset) {
        if (!tokenset.id_token) {
          return tokenset;
        }
        return _this5.decryptIdToken(tokenset, 'id_token').then(function () {
          return _this5.validateIdToken(tokenset, null, 'token', null);
        });
      });
    }

    /**
     * @name userinfo
     * @api public
     */

  }, {
    key: 'userinfo',
    value: function userinfo(accessToken, options) {
      var _this6 = this;

      var token = accessToken;
      var opts = _.merge({
        verb: 'get',
        via: 'header'
      }, options);

      if (token instanceof TokenSet) {
        if (!token.access_token) {
          return Promise.reject(new Error('access_token not present in TokenSet'));
        }
        token = token.access_token;
      }

      var verb = String(opts.verb).toLowerCase();
      var httpOptions = void 0;

      switch (opts.via) {
        case 'query':
          assert.equal(verb, 'get', 'providers should only parse query strings for GET requests');
          httpOptions = { query: { access_token: token } };
          break;
        case 'body':
          assert.equal(verb, 'post', 'can only send body on POST');
          httpOptions = { body: { access_token: token } };
          break;
        default:
          httpOptions = { headers: { Authorization: bearer(token) } };
      }

      if (opts.params) {
        if (verb === 'post') {
          _.defaultsDeep(httpOptions, { body: opts.params });
        } else {
          _.defaultsDeep(httpOptions, { query: opts.params });
        }
      }

      return got[verb](this.issuer.userinfo_endpoint, this.issuer.httpOptions(httpOptions)).then(expectResponse(200)).then(function (response) {
        if (JWT_CONTENT.exec(response.headers['content-type'])) {
          return Promise.resolve(response.body).then(function (jwt) {
            return _this6.decryptIdToken(jwt, 'userinfo');
          }).then(function (jwt) {
            if (!_this6.userinfo_signed_response_alg) return JSON.parse(jwt);
            return _this6.validateIdToken(jwt, null, 'userinfo', null).then(function (valid) {
              return JSON.parse(base64url.decode(valid.split('.')[1]));
            });
          });
        }

        return JSON.parse(response.body);
      }).then(function (parsed) {
        if (accessToken.id_token) {
          assert.equal(getSub(accessToken.id_token), parsed.sub, 'userinfo sub mismatch');
        }

        return parsed;
      }).catch(errorHandler);
    }

    /**
     * @name derivedKey
     * @api private
     */

  }, {
    key: 'derivedKey',
    value: function derivedKey(len) {
      var _this7 = this;

      var cacheKey = len + '_key';
      if (instance(this)[cacheKey]) {
        return Promise.resolve(instance(this)[cacheKey]);
      }

      var derivedBuffer = crypto.createHash('sha256').update(this.client_secret).digest().slice(0, len / 8);

      return jose.JWK.asKey({ k: base64url(derivedBuffer), kty: 'oct' }).then(function (key) {
        instance(_this7)[cacheKey] = key;
        return key;
      });
    }

    /**
     * @name joseSecret
     * @api private
     */

  }, {
    key: 'joseSecret',
    value: function joseSecret(alg) {
      var _this8 = this;

      if (String(alg).match(/^A(128|192|256)(GCM)?KW$/)) {
        return this.derivedKey(RegExp.$1);
      }

      if (instance(this).jose_secret) {
        return Promise.resolve(instance(this).jose_secret);
      }

      return jose.JWK.asKey({ k: base64url(this.client_secret), kty: 'oct' }).then(function (key) {
        instance(_this8).jose_secret = key;
        return key;
      });
    }

    /**
     * @name grant
     * @api public
     */

  }, {
    key: 'grant',
    value: function grant(body) {
      assert(this.issuer.token_endpoint, 'issuer must be configured with token endpoint');
      return this.authenticatedPost('token', { body: _.omitBy(body, _.isUndefined) }).then(expectResponse(200)).then(function (response) {
        return new TokenSet(JSON.parse(response.body));
      });
    }

    /**
     * @name revoke
     * @api public
     */

  }, {
    key: 'revoke',
    value: function revoke(token, hint) {
      assert(this.issuer.revocation_endpoint, 'issuer must be configured with revocation endpoint');
      assert(!hint || typeof hint === 'string', 'hint must be a string');

      var body = { token: token };
      if (hint) body.token_type_hint = hint;
      return this.authenticatedPost('revocation', { body: body }).then(function (response) {
        if (response.body) {
          return JSON.parse(response.body);
        }
        return {};
      });
    }

    /**
     * @name introspect
     * @api public
     */

  }, {
    key: 'introspect',
    value: function introspect(token, hint) {
      assert(this.issuer.introspection_endpoint, 'issuer must be configured with introspection endpoint');
      assert(!hint || typeof hint === 'string', 'hint must be a string');

      var body = { token: token };
      if (hint) body.token_type_hint = hint;
      return this.authenticatedPost('introspection', { body: body }).then(expectResponse(200)).then(function (response) {
        return JSON.parse(response.body);
      });
    }

    /**
     * @name fetchDistributedClaims
     * @api public
     */

  }, {
    key: 'fetchDistributedClaims',
    value: function fetchDistributedClaims(claims, accessTokens) {
      var _this9 = this;

      var distributedSources = _.pickBy(claims._claim_sources, function (def) {
        return !!def.endpoint;
      });
      var tokens = accessTokens || {};

      return Promise.all(_.map(distributedSources, function (def, sourceName) {
        var opts = {
          headers: { Authorization: bearer(def.access_token || tokens[sourceName]) }
        };

        return got(def.endpoint, _this9.issuer.httpOptions(opts)).then(function (response) {
          return claimJWT.call(_this9, response.body);
        }, errorHandler).then(function (data) {
          delete claims._claim_sources[sourceName];
          _.forEach(claims._claim_names, assignClaim(claims, data, sourceName));
        }).catch(assignErrSrc(sourceName));
      })).then(function () {
        return cleanUpClaims(claims);
      });
    }

    /**
     * @name unpackAggregatedClaims
     * @api public
     */

  }, {
    key: 'unpackAggregatedClaims',
    value: function unpackAggregatedClaims(claims) {
      var _this10 = this;

      var aggregatedSources = _.pickBy(claims._claim_sources, function (def) {
        return !!def.JWT;
      });

      return Promise.all(_.map(aggregatedSources, function (def, sourceName) {
        var decoded = claimJWT.call(_this10, def.JWT);

        return decoded.then(function (data) {
          delete claims._claim_sources[sourceName];
          _.forEach(claims._claim_names, assignClaim(claims, data, sourceName));
        }).catch(assignErrSrc(sourceName));
      })).then(function () {
        return cleanUpClaims(claims);
      });
    }

    /**
     * @name authenticatedPost
     * @api private
     */

  }, {
    key: 'authenticatedPost',
    value: function authenticatedPost(endpoint, httpOptions) {
      var _this11 = this;

      return Promise.resolve(this.authFor(endpoint)).then(function (auth) {
        return got.post(_this11.issuer[endpoint + '_endpoint'], _this11.issuer.httpOptions(_.merge(httpOptions, auth))).catch(errorHandler);
      });
    }

    /**
     * @name createSign
     * @api private
     */

  }, {
    key: 'createSign',
    value: function createSign(endpoint) {
      var _this12 = this;

      var alg = this[endpoint + '_endpoint_auth_signing_alg'];
      switch (this[endpoint + '_endpoint_auth_method']) {
        case 'client_secret_jwt':
          return this.joseSecret().then(function (key) {
            if (!alg) {
              alg = _.find(_this12.issuer[endpoint + '_endpoint_auth_signing_alg_values_supported'], function (signAlg) {
                return key.algorithms('sign').indexOf(signAlg) !== -1;
              });
            }

            return jose.JWS.createSign({
              fields: { alg: alg, typ: 'JWT' },
              format: format
            }, { key: key, reference: false });
          });
        case 'private_key_jwt':
          {
            if (!alg) {
              var algz = _.chain(instance(this).keystore.all()).map(function (key) {
                return key.algorithms('sign');
              }).flatten().uniq().value();

              alg = _.find(this.issuer[endpoint + '_endpoint_auth_signing_alg_values_supported'], function (signAlg) {
                return algz.indexOf(signAlg) !== -1;
              });
            }

            var key = instance(this).keystore.get({ alg: alg, use: 'sig' });
            assert(key, 'no valid key found');

            return Promise.resolve(jose.JWS.createSign({
              fields: { alg: alg, typ: 'JWT' },
              format: format
            }, { key: key, reference: true }));
          }
        /* istanbul ignore next */
        default:
          throw new Error('createSign only works for _jwt token auth methods');
      }
    }

    /**
     * @name authFor
     * @api private
     */

  }, {
    key: 'authFor',
    value: function authFor(endpoint) {
      var _this13 = this;

      switch (this[endpoint + '_endpoint_auth_method'] || this.token_endpoint_auth_method) {
        case 'none':
          return {
            body: {
              client_id: this.client_id
            }
          };
        case 'client_secret_post':
          return {
            body: {
              client_id: this.client_id,
              client_secret: this.client_secret
            }
          };
        case 'private_key_jwt':
        case 'client_secret_jwt':
          {
            var timestamp = now();
            return this.createSign(endpoint).then(function (sign) {
              return sign.update(JSON.stringify({
                iat: timestamp,
                exp: timestamp + 60,
                jti: uuid(),
                iss: _this13.client_id,
                sub: _this13.client_id,
                aud: _this13.issuer[endpoint + '_endpoint']
              })).final().then(function (client_assertion) {
                // eslint-disable-line camelcase, arrow-body-style
                return { body: {
                    client_assertion: client_assertion,
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                  } };
              });
            });
          }
        default:
          {
            var value = new Buffer(this.client_id + ':' + this.client_secret).toString('base64');
            return { headers: { Authorization: 'Basic ' + value } };
          }
      }
    }

    /**
     * @name inspect
     * @api public
     */

  }, {
    key: 'inspect',
    value: function inspect() {
      return util.format('Client <%s>', this.client_id);
    }

    /**
     * @name register
     * @api public
     */

  }, {
    key: 'requestObject',


    /**
     * @name requestObject
     * @api public
     */
    value: function requestObject(input, algorithms) {
      var _this14 = this;

      assert.equal(typeof input === 'undefined' ? 'undefined' : _typeof(input), 'object', 'pass an object as the first argument');
      var request = input || {};
      var algs = algorithms || {};

      _.defaults(algs, {
        sign: this.request_object_signing_alg,
        encrypt: {
          alg: this.request_object_encryption_alg,
          enc: this.request_object_encryption_enc
        }
      }, {
        sign: 'none'
      });

      var signed = function () {
        var alg = algs.sign;
        var header = { alg: alg, typ: 'JWT' };
        var payload = JSON.stringify(_.defaults({}, request, {
          iss: _this14.client_id,
          aud: _this14.issuer.issuer,
          client_id: _this14.client_id
        }));

        if (alg === 'none') {
          return Promise.resolve([base64url(JSON.stringify(header)), base64url(payload), ''].join('.'));
        }

        var symmetrical = alg.startsWith('HS');

        var getKey = function () {
          if (symmetrical) return _this14.joseSecret();
          var keystore = instance(_this14).keystore;

          assert(keystore, 'no keystore present for client, cannot sign using ' + alg);
          var key = keystore.get({ alg: alg, use: 'sig' });
          assert(key, 'no key to sign with found for ' + alg);
          return Promise.resolve(key);
        }();

        return getKey.then(function (key) {
          return jose.JWS.createSign({
            fields: header,
            format: format
          }, { key: key, reference: !symmetrical });
        }).then(function (sign) {
          return sign.update(payload).final();
        });
      }();

      if (!algs.encrypt.alg) return signed;
      var fields = { alg: algs.encrypt.alg, enc: algs.encrypt.enc, cty: 'JWT' };

      /* eslint-disable arrow-body-style */
      return this.issuer.key({
        alg: algs.encrypt.alg,
        enc: algs.encrypt.enc,
        use: 'enc'
      }, true).then(function (key) {
        return signed.then(function (cleartext) {
          return jose.JWE.createEncrypt({ format: format, fields: fields }, { key: key }).update(cleartext).final();
        });
      });
      /* eslint-enable arrow-body-style */
    }
  }, {
    key: 'metadata',
    get: function get() {
      return instance(this).metadata;
    }

    /**
     * @name fromUri
     * @api public
     */

  }], [{
    key: 'register',
    value: function register(properties, opts) {
      var _this15 = this;

      var options = function () {
        if (!opts) return {};
        if (_.isPlainObject(opts)) return opts;
        return { keystore: deprecatedKeystore(opts) };
      }();

      var keystore = options.keystore;
      var initialAccessToken = options.initialAccessToken;

      assert(this.issuer.registration_endpoint, 'issuer does not support dynamic registration');

      if (keystore !== undefined && !(properties.jwks || properties.jwks_uri)) {
        assert(jose.JWK.isKeyStore(keystore), 'keystore must be an instance of jose.JWK.KeyStore');
        assert(keystore.all().every(function (key) {
          if (key.kty === 'RSA' || key.kty === 'EC') {
            try {
              key.toPEM(true);
            } catch (err) {
              return false;
            }
            return true;
          }
          return false;
        }), 'keystore must only contain private EC or RSA keys');
        properties.jwks = keystore.toJSON();
      }

      var headers = { 'Content-Type': 'application/json' };

      if (initialAccessToken) headers.Authorization = 'Bearer ' + initialAccessToken;

      return got.post(this.issuer.registration_endpoint, this.issuer.httpOptions({
        headers: headers,
        body: JSON.stringify(properties)
      })).then(expectResponse(201)).then(function (response) {
        return new _this15(JSON.parse(response.body), keystore);
      }).catch(errorHandler);
    }
  }, {
    key: 'fromUri',
    value: function fromUri(uri, token) {
      var _this16 = this;

      return got(uri, this.issuer.httpOptions({
        headers: { Authorization: bearer(token) }
      })).then(expectResponse(200)).then(function (response) {
        return new _this16(JSON.parse(response.body));
      }, errorHandler);
    }
  }]);

  return Client;
}();

Object.defineProperty(Client.prototype, 'grantAuth', {
  get: util.deprecate( /* istanbul ignore next */function grantAuth() {
    return this.authFor('token');
  }, 'client#grantAuth is deprecated')
});

module.exports = Client;