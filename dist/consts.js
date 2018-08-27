'use strict';

var pkg = require('../package.json');

var USER_AGENT = pkg.name + '/' + pkg.version + ' (' + pkg.homepage + ')';

var DISCOVERY = '/.well-known/openid-configuration';
var WEBFINGER = '/.well-known/webfinger';
var REL = 'http://openid.net/specs/connect/1.0/issuer';

var CLIENT_DEFAULTS = {
  application_type: 'web',
  grant_types: ['authorization_code'],
  id_token_signed_response_alg: 'RS256',
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic'
};

var ISSUER_DEFAULTS = {
  claims_parameter_supported: false,
  grant_types_supported: ['authorization_code', 'implicit'],
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
  response_modes_supported: ['query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic']
};

var CALLBACK_PROPERTIES = ['access_token', 'code', 'error', 'error_description', 'expires_in', 'id_token', 'state', 'token_type', 'session_state'];

var DEFAULT_HTTP_OPTIONS = {
  followRedirect: false,
  headers: { 'User-Agent': USER_AGENT },
  retries: 0,
  timeout: 1500
};

var JWT_CONTENT = /^application\/jwt/;

module.exports.CALLBACK_PROPERTIES = CALLBACK_PROPERTIES;
module.exports.CLIENT_DEFAULTS = CLIENT_DEFAULTS;
module.exports.DEFAULT_HTTP_OPTIONS = DEFAULT_HTTP_OPTIONS;
module.exports.ISSUER_DEFAULTS = ISSUER_DEFAULTS;
module.exports.JWT_CONTENT = JWT_CONTENT;
module.exports.USER_AGENT = USER_AGENT;
module.exports.DISCOVERY = DISCOVERY;
module.exports.REL = REL;
module.exports.WEBFINGER = WEBFINGER;