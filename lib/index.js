
/**
 * deps
 */

var http = require('http')
  , crypto = require('crypto');

/**
 * 3rd deps
 */

var _ = require('lodash')
  , async = require('async')
  , request = require('request');

/**
 * constructor
 * possible options:
 * @param appId
 * @param secretKey
 * @param serverURL
 * @param host
 * @param port
 * @param grant optional
 * @param token optional
 */

function OAuth2Client(options, callback) {

  this.options = options || {};

  if (!_.size(options)) {
    throw new Error(
      'options appId, secretKey, serverURL are required'
    );
  }

  this.options.host = options.host || 'localhost';
  this.options.port = options.port || 80;
  this.options.protocol = options.protocol || 'http';

  this.url = [
    this.options.protocol,
    '://',
    this.options.host,
    ':',
    this.options.port
  ].join('');

  if (options.grant) this.GRANT = options.grant;
  if (options.token) this.TOKEN = options.token;

  async.series({

    grant: function(next) {
      if (!this.GRANT) {
        this.getGrant(function(err, grant) {
          if (err) throw new Error(err);
          next(null, grant);
        });
      }
    }.bind(this),

    token: function(next) {
      if (this.GRANT && !this.TOKEN) {
        this.getToken(function(err, token) {
          if (err) throw new Error(err);
          next(null, token);
        });
      }
    }.bind(this)

  }, callback);

}

module.exports = OAuth2Client;

/**
 * 
 */

OAuth2Client.prototype.getGrant = function(callback) {

  request({
    method: 'POST',
    uri: this.url + '/auth/grant',
    json: { appId: this.options.appId }
  },

  function(err, res, body) {
    this.GRANT = body;
    callback(null, body);
  }.bind(this));
  
};

/**
 * 
 */

OAuth2Client.prototype.getToken = function(callback) {
  var cipher = crypto.createCipher('aes-256-cbc', this.options.secretKey)
    , encryptedGrant = cipher.update(this.GRANT, 'utf8', 'base64') + cipher.final('base64');

  request({
    method: 'POST',
    uri: this.url + '/auth/token',
    json: { 
      appId: this.options.appId,
      encryptedGrant: encryptedGrant
    }
  },

  function(err, res, body) {
    this.TOKEN = body;
    callback(null, body);
  }.bind(this));

};

