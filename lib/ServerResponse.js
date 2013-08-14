var events = require('events')
    , util = require('util');

function ServerResponse(socket) {
    events.EventEmitter.call(this);
    this._socket = socket;
    this.sendDate = true;
    var self = this;
    this._socket.on('close', function (had_error) { self.emit('close', had_error); });
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
    this._socket._requestContext.responseStarted = true;
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
