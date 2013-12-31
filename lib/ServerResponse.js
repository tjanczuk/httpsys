var events = require('events')
    , util = require('util');

function ServerResponse(socket) {
    events.EventEmitter.call(this);
    this._socket = socket;
    this.sendDate = true;
    var self = this;
    // Pass on internal socket events up to listeners on the Response object
    // (which is what's exposed in the connect's http pipeline)
    this._socket.on('finish', function () { self.emit('finish'); });
    this._socket.on('close', function (had_error) { self.emit('close', had_error); });
    // Socket will raise 'header' event when headers have been committed. This is
    // consistent with how 'connect' library patches ServerResponse. 
    this._socket.on('header', function () {
        // Additionally it patches the .headerSent property, so we don't set it directly but via ._header
        // (see 'patch.js' in 'connect' module lib folder).
        self.headersSent = self._header = true;
        // _headers is also assumed on the response object by 'connect' module
        self._headers = self._socket._requestContext.headers;
    });
};

util.inherits(ServerResponse, events.EventEmitter);

ServerResponse.prototype.writeHead = function (statusCode, reasonPhrase, headers) {
    this._socket._requestContext.responseStarted = true;
    return this._socket._writeHead(statusCode, reasonPhrase, headers);
};

ServerResponse.prototype.destroy = function (error) {
    return this._socket.destroy(error);
};

ServerResponse.prototype.write = function(chunk, encoding, isEnd) {
    // ensure statusCode property is set on the Response object (as
    // per node's documentation), and allow middleware to set it
    if (!this._socket._requestContext.responseStarted) {
        this._socket._requestContext.responseStarted = true;
        this._socket._requestContext.statusCode = this.statusCode = this.statusCode || this._socket._requestContext.statusCode;
    }
    return this._socket.write(chunk, encoding, isEnd);
};

ServerResponse.prototype.end = function (chunk, encoding) {
    return this.write(chunk, encoding, true);
};

ServerResponse.prototype.writeContinue = function () {
    throw new Error('The writeContinue method is not supported because 100 Continue '
        + ' responses are sent automatically by HTTP.SYS.');
};

ServerResponse.prototype.setHeader = function (name, value) {
    return this._socket._setHeader(name, value);
};

ServerResponse.prototype.getHeader = function (name) {
    return this._socket._getHeader(name); 
};

ServerResponse.prototype.removeHeader = function (name) {
    return this._socket._removeHeader(name);
};

ServerResponse.prototype.addTrailers = function () {
    // TODO support for trailers
    throw new Error('Support for trailers is not yet implemented.');
}

module.exports = ServerResponse;
