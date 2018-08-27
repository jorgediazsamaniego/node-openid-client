'use strict';

var isStandardError = require('./is_standard_error');
var OpenIdConnectError = require('./open_id_connect_error');

module.exports = function gotErrorHandler(err) {
  if (isStandardError(err)) throw new OpenIdConnectError(err.response.body, err.response);
  throw err;
};