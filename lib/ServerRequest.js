var events = require('events')
    , util = require('util');

function ServerRequest(socket) {
    events.EventEmitter.call(this);
    this.socket = socket;
    for (var i in this.socket._requestContext.req) {
        this[i] = this.socket._requestContext.req[i];
    }

    this.httpVersion = this.httpVersionMajor + '.' + this.httpVersionMinor;
    var self = this;
};

util.inherits(ServerRequest, events.EventEmitter);

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
