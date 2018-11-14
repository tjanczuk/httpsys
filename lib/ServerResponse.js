var events = require('events')
    ,util = require('util')
    , Stream = require('stream')
    , HttpStatus = require('http-status-codes');

function ServerResponse(socket) {
    
    Stream.call(this);
    
    // `outputSize` is an approximate measure of how much data is queued on this
    // response. `_onPendingData` will be invoked to update similar global
    // per-connection counter. That counter will be used to pause/unpause the
    // TCP socket and HTTP Parser and thus handle the backpressure.
    this.outputSize = 0;
    
    //need to initialise this to 200 to allow serve-static module to correctly check for fileCreatedDate
	//not modified. see module isCachable() in nodejs\node_modules\serve-static\node_modules\send\index.js
	//this was originally commented-out to prevent browser range request issues. The was due to javascript httpsys
	//code not correctly returning 206/200, the result was page downloads never completed (just occasional froze). 
	//However have now tested in 11.3 which now uses http.sys I cannot see any problems.
    this.statusCode = 200;

    this.writable = true;
    
    this._last = false;
    this.chunkedEncoding = false;
    this.shouldKeepAlive = true;
    this.useChunkedEncodingByDefault = true;
    
    this._removedHeader = {};
    
    this._contentLength = null;
    this._hasBody = true;
    this._trailer = '';
    
    this.finished = false;
    this._headerSent = false;
    
    this.connection = null;
    this._header = null;
    this._headers = null;
    this._headerNames = {};
    
    this._onPendingData = null;
    
    /***************************/

    events.EventEmitter.call(this);
    this._socket = socket;
    this.sendDate = true;
    var self = this;
    this._socket.on('close', function (had_error) { self.emit('close', had_error); });

    this._socket.on('drain', function () {
        self.emit('drain');
    });
};

util.inherits(ServerResponse, events.EventEmitter);
util.inherits(ServerResponse, Stream);


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
    //if this is the first and last block then make 
    //sure the status code is set correctly
    if (!this._socket._requestContext.responseStarted && this.statusCode) {
        this._socket._requestContext.statusCode = this.statusCode;
        this._socket._requestContext.reason = HttpStatus.getStatusText(this.statusCode) || "OK";
    }
    return this.write(chunk, encoding, true);
};

ServerResponse.prototype.writeContinue = function () {
    throw new Error('The writeContinue method is not supported because 100 Continue '
        + ' responses are sent automatically by HTTP.SYS.');
};

ServerResponse.prototype.setHeader = function (name, value) {
    //JPW added: express requires headers in object _headers
    if (!this._headers) {
        this._headers = {};
    }
    this._headers [name.toLowerCase()] = value.toString();;
    return this._socket._setHeader(name, value);
};

ServerResponse.prototype.getHeader = function (name) {
    return this._socket._getHeader(name); 
};

ServerResponse.prototype.removeHeader = function (name) {
    //JPW added: express requires headers in object _headers
    if (this._header && this._headers[name.toLowerCase()]) {
        delete this._headers[name.toLowerCase()];
    }
    return this._socket._removeHeader(name);
};

ServerResponse.prototype.addTrailers = function () {
    // TODO support for trailers
    throw new Error('Support for trailers is not yet implemented.');
}

module.exports = ServerResponse;
