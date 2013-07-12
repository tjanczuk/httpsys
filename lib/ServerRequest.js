var httpsys = require('./httpsys_native.js')
    , events = require('events')
    , util = require('util');

function ServerRequest(requestContext) {
    events.EventEmitter.call(this);
    this._requestContext = requestContext;
    for (var i in requestContext.req) {
        this[i] = requestContext.req[i];
    }

    this.httpVersion = this.httpVersionMajor + '.' + this.httpVersionMinor;
    this._encoding = 'binary';
};

util.inherits(ServerRequest, events.EventEmitter);

ServerRequest.prototype.pause = function () {
    this._paused = true;
};

ServerRequest.prototype.resume = function () {
    if (this._paused) {
        if (!this._requestContext.asyncPending && !this._requestContext.requestRead) {
            httpsys.httpsys_resume(this._requestContext);
        }

        delete this._paused;
    }
};

ServerRequest.prototype.setEncoding = function (encoding) {
    this._encoding = encoding || 'utf8';
};

ServerRequest.prototype._on_request_body = function (args) {
    if (this._encoding === 'binary') {
        this.emit('data', args.data);
    }
    else {
        this.emit('data', args.data.toString(this._encoding));
    }
};

ServerRequest.prototype._on_end_request = function () {
    this._requestContext.requestRead = true;
    this.emit('end');

    // Signal the response to start sending cached response content if any
    // had been accumulated while the response was being received.

    this._requestContext.res._initiate_send_next();
};

module.exports = ServerRequest;
