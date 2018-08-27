"use strict";

var request = require('request');
var got = require('got');
var PCancelable = require('p-cancelable');
var querystring = require('querystring');
var isPlainObj = require('is-plain-obj');

function mapGotOptions(gotOptions) {
  var body = gotOptions.body;
  var headers = {};

  if (gotOptions.body && isPlainObj(gotOptions.body) && !gotOptions.json) {
    body = querystring.stringify(gotOptions.body);
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }

  return Object.assign({}, gotOptions, {
    headers: Object.assign({}, gotOptions.headers, headers),
    body: body || undefined,
    qs: gotOptions.query
  });
}

/**
 * A PCancelable wrapper around request that transforms `got`-like requests
 * into `request` requests.
 *
 * @param {string} url the URL to call
 * @param {object} options
 * @returns {Promise}
 */
function req(url, gotOptions) {
  return new PCancelable(function (onCancel, resolve, reject) {
    var requestOptions = mapGotOptions(gotOptions);
    request(url, requestOptions, function (error, response) {
      var limitStatusCode = requestOptions.followRedirect ? 299 : 399;

      if (error) {
        return reject(error);
      }

      var statusCode = response.statusCode;

      if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
        var err = new got.HTTPError(response.statusCode, response.headers, requestOptions);
        err.response = response;
        return reject(err);
      }

      return resolve(response);
    });
  });
}

var helpers = ['get', 'post', 'put', 'patch', 'head', 'delete'];

helpers.forEach(function (el) {
  req[el] = function (url, opts) {
    return req(url, Object.assign({}, opts, { method: el }));
  };
});

req.HTTPError = got.HTTPError;

module.exports = req;