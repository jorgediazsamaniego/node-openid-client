"use strict";

const request = require('request');
const got = require('got');
const PCancelable = require('p-cancelable');
const querystring = require('querystring');
const isPlainObj = require('is-plain-obj');


function mapGotOptions(gotOptions) {
  let body = gotOptions.body;

  if (gotOptions.body && isPlainObj(gotOptions.body)) {
    body = querystring.stringify(gotOptions.body);
  }

  return Object.assign({}, gotOptions, {
    headers: Object.assign({}, gotOptions.headers),
    body: body || undefined,
    qs: gotOptions.query,
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
  return new PCancelable((onCancel, resolve, reject) => {
    const requestOptions = mapGotOptions(gotOptions);
    request(url, requestOptions, (error, response) => {
      const limitStatusCode = requestOptions.followRedirect ? 299 : 399;

      if (error) {
        return reject(error);
      }

      const statusCode = response.statusCode;

      if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
        const err = new got.HTTPError(response.statusCode, response.headers, requestOptions);
        err.response = response;
        return reject(err);
      }

      return resolve(response);
    });
  });
}

const helpers = [
  'get',
  'post',
  'put',
  'patch',
  'head',
  'delete',
];

helpers.forEach((el) => {
  req[el] = (url, opts) => req(url, Object.assign({}, opts, { method: el }));
});

req.HTTPError = got.HTTPError;

module.exports = req;
