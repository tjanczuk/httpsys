var events = require('events')
    , util = require('util');

// http://msdn.microsoft.com/en-us/library/windows/desktop/aa377188(v=vs.85).aspx

var certErrors = {
    0x800B0101: 'CERT_E_EXPIRED',
    0x800B0112: 'CERT_E_UNTRUSTEDCA',
    0x80096004: 'TRUST_E_CERT_SIGNATURE',
    0x80092010: 'CRYPT_E_REVOKED',
    0x800B0109: 'CERT_E_UNTRUSTEDROOT',
    0x800B0110: 'CERT_E_WRONG_USAGE',
    0x80092012: 'CRYPT_E_NO_REVOCATION_CHECK',
    0x80092013: 'CRYPT_E_REVOCATION_OFFLINE',
    0x800B010A: 'CERT_E_CHAINING'
};

function ServerRequest(socket) {
    events.EventEmitter.call(this);
    this.socket = this.connection = socket;

    var clientCertInfo = this.socket._requestContext.req.clientCertInfo;
    if (clientCertInfo) {
        delete this.socket._requestContext.req.clientCertInfo;

        if (!isNaN(clientCertInfo.cert.valid_from)) {
            clientCertInfo.cert.valid_from = new Date(clientCertInfo.cert.valid_from * 1000).toUTCString();
        }

        if (!isNaN(clientCertInfo.cert.valid_to)) {
            clientCertInfo.cert.valid_to = new Date(clientCertInfo.cert.valid_to * 1000).toUTCString();
        }

        if (Buffer.isBuffer(clientCertInfo.cert.fingerprint)) {
            var hash = [];
            for (var i = 0; i < clientCertInfo.cert.fingerprint.length; i++) {
                hash.push(clientCertInfo.cert.fingerprint.toString('hex', i, i + 1).toUpperCase());
            }

            clientCertInfo.cert.fingerprint = hash.join(':');
        }

        var authorizationError = clientCertInfo.authorizationError;
        if (authorizationError === 0) {
            clientCertInfo.authorizationError = undefined;
        }
        else {
            clientCertInfo.authorizationError = 
                certErrors[clientCertInfo.authorizationError] 
                || ('0x' + clientCertInfo.authorizationError.toString(16));
        }

        this.client = {
            authorized: clientCertInfo.authorizationError === undefined,
            authorizationError: clientCertInfo.authorizationError,
            getPeerCertificate: function () {
                return clientCertInfo.cert || {};
            }
        }
    }
    else {
        this.client = {};
    }
    
    for (var i in this.socket._requestContext.req) {
        this[i] = this.socket._requestContext.req[i];
    }

    this.httpVersion = this.httpVersionMajor + '.' + this.httpVersionMinor;
    var self = this;
    this.socket.on('close', function (had_error) { self.emit('close', had_error); });
};

util.inherits(ServerRequest, events.EventEmitter);

ServerRequest.prototype.destroy = function (error) {
    return this.socket.destroy(error);
};

ServerRequest.prototype.pause = function () {
    this.socket.pause();
};

ServerRequest.prototype.resume = function () {
    this.socket.resume();
};

ServerRequest.prototype.setEncoding = function (encoding) {
    this.socket.setEncoding(encoding);
};

ServerRequest.prototype._subscribe = function () {
    var self = this;
    // TODO promote other Socket events to ServerRequest?
    this.socket.on('data', function (chunk) { self.emit('data', chunk); });
    this.socket.on('end', function () { self.emit('end'); });
};

module.exports = ServerRequest;
