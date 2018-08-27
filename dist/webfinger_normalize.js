'use strict';

// Credit: https://github.com/rohe/pyoidc/blob/master/src/oic/utils/webfinger.py

// -- Normalization --
// A string of any other type is interpreted as a URI either the form of scheme
// "://" authority path-abempty [ "?" query ] [ "#" fragment ] or authority
// path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986] and is
// normalized according to the following rules:
//
// If the user input Identifier does not have an RFC 3986 [RFC3986] scheme
// portion, the string is interpreted as [userinfo "@"] host [":" port]
// path-abempty [ "?" query ] [ "#" fragment ] per RFC 3986 [RFC3986].
// If the userinfo component is present and all of the path component, query
// component, and port component are empty, the acct scheme is assumed. In this
// case, the normalized URI is formed by prefixing acct: to the string as the
// scheme. Per the 'acct' URI Scheme [I‑D.ietf‑appsawg‑acct‑uri], if there is an
// at-sign character ('@') in the userinfo component, it needs to be
// percent-encoded as described in RFC 3986 [RFC3986].
// For all other inputs without a scheme portion, the https scheme is assumed,
// and the normalized URI is formed by prefixing https:// to the string as the
// scheme.
// If the resulting URI contains a fragment portion, it MUST be stripped off
// together with the fragment delimiter character "#".
// The WebFinger [I‑D.ietf‑appsawg‑webfinger] Resource in this case is the
// resulting URI, and the WebFinger Host is the authority component.
//
// Note: Since the definition of authority in RFC 3986 [RFC3986] is
// [ userinfo "@" ] host [ ":" port ], it is legal to have a user input
// identifier like userinfo@host:port, e.g., alice@example.com:8080.

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var assert = require('assert');

var PORT = /^\d+$/;

function hasScheme(input) {
  if (input.includes('://')) return true;

  var authority = input.replace(/(\/|\?)/g, '#').split('#')[0];
  if (authority.includes(':')) {
    var index = authority.indexOf(':');
    var hostOrPort = authority.slice(index + 1);
    if (!PORT.exec(hostOrPort)) return true;
  }

  return false;
}

function acctSchemeAssumed(input) {
  if (!input.includes('@')) return false;
  var parts = input.split('@');
  var host = parts[parts.length - 1];
  return !(host.includes(':') || host.includes('/') || host.includes('?'));
}

function normalize(input) {
  assert(input, 'nothing to normalize');
  assert.equal(typeof input === 'undefined' ? 'undefined' : _typeof(input), 'string', 'input must be a string');

  var output = void 0;
  if (hasScheme(input)) {
    output = input;
  } else if (acctSchemeAssumed(input)) {
    output = 'acct:' + input;
  } else {
    output = 'https://' + input;
  }

  return output.split('#')[0];
}

module.exports = normalize;