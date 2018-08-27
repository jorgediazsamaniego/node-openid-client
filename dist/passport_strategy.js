'use strict';

/* eslint-disable no-underscore-dangle */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _ = require('lodash');
var uuid = require('uuid');
var url = require('url');
var assert = require('assert');
var OpenIdConnectError = require('./open_id_connect_error');
var Client = require('./client');

function verified(err, user, info) {
  var add = info || {};
  if (err) {
    this.error(err);
  } else if (!user) {
    this.fail(add);
  } else {
    this.success(user, add);
  }
}

/**
 * @name constructor
 * @api public
 */
function OpenIDConnectStrategy(options, verify) {
  var opts = function () {
    if (options instanceof Client) return { client: options };
    return options;
  }();

  var client = opts.client;

  assert.equal(client instanceof Client, true);
  assert.equal(typeof verify === 'undefined' ? 'undefined' : _typeof(verify), 'function');

  assert(client.issuer && client.issuer.issuer, 'client must have an issuer with an identifier');

  this._client = client;
  this._issuer = client.issuer;
  this._verify = verify;
  this._params = opts.params || {};
  var params = this._params;

  this.name = url.parse(client.issuer.issuer).hostname;

  if (!params.response_type) params.response_type = _.get(client, 'response_types[0]', 'code');
  if (!params.redirect_uri) params.redirect_uri = _.get(client, 'redirect_uris[0]');
  if (!params.scope) params.scope = 'openid';
}

OpenIDConnectStrategy.prototype.authenticate = function authenticate(req, options) {
  var _this = this;

  var client = this._client;
  var issuer = this._issuer;
  try {
    if (!req.session) throw new Error('authentication requires session support when using state, max_age or nonce');
    var reqParams = client.callbackParams(req);
    var sessionKey = 'oidc:' + url.parse(issuer.issuer).hostname;

    /* start authentication request */
    if (_.isEmpty(reqParams)) {
      // provide options objecti with extra authentication parameters
      var _opts = _.defaults({}, options, this._params, {
        state: uuid()
      });

      if (!_opts.nonce && _opts.response_type.includes('id_token')) {
        _opts.nonce = uuid();
      }

      req.session[sessionKey] = _.pick(_opts, 'nonce', 'state', 'max_age');
      this.redirect(client.authorizationUrl(_opts));
      return;
    }
    /* end authentication request */

    /* start authentication response */
    var session = req.session[sessionKey];
    var state = _.get(session, 'state');
    var maxAge = _.get(session, 'max_age');
    var nonce = _.get(session, 'nonce');

    try {
      delete req.session[sessionKey];
    } catch (err) {}

    var opts = _.defaults({}, options, {
      redirect_uri: this._params.redirect_uri
    });

    var checks = { state: state, nonce: nonce, max_age: maxAge };
    var callback = client.authorizationCallback(opts.redirect_uri, reqParams, checks).then(function (tokenset) {
      var result = { tokenset: tokenset };
      return result;
    });

    var loadUserinfo = this._verify.length > 2 && client.issuer.userinfo_endpoint;

    if (loadUserinfo) {
      callback = callback.then(function (result) {
        if (result.tokenset.access_token) {
          var userinfoRequest = client.userinfo(result.tokenset);
          return userinfoRequest.then(function (userinfo) {
            result.userinfo = userinfo;
            return result;
          });
        }

        return result;
      });
    }

    callback.then(function (result) {
      if (loadUserinfo) {
        _this._verify(result.tokenset, result.userinfo, verified.bind(_this));
      } else {
        _this._verify(result.tokenset, verified.bind(_this));
      }
    }).catch(function (error) {
      if (error instanceof OpenIdConnectError && error.error !== 'server_error' && !error.error.startsWith('invalid')) {
        _this.fail(error);
      } else {
        _this.error(error);
      }
    });
    /* end authentication response */
  } catch (err) {
    this.error(err);
  }
};

module.exports = OpenIDConnectStrategy;