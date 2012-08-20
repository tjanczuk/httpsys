var httpsys = require(process.env.HTTPSYS_NATIVE || './httpsys.node')
    , events = require('events')
    , util = require('util');

// Currently active HTTP[S] servers (Server instances), keyed by HTTP.SYS's request queue ID
var servers = {};

// This is a v-table mapping event types defined by uv_httpsys_event_type in httpsys.h
// to action methods. This is used in Server.prototype._dispatch.
// Order is important and must match uv_httpsys_event_type.
var nativeEvents = [
    undefined,                        // 0 - unused
    '_on_error_initializing_request', // 1
    '_on_error_new_request',          // 2
    '_on_new_request',
    '_on_error_initializing_read_request_body',
    '_on_end_request',
    '_on_error_read_request_body',
    '_on_request_body',
    '_on_headers_written',
    '_on_error_writing_headers',
    '_on_body_written',
    '_on_error_writing_body'
];

httpsys.httpsys_init({
    initialBufferSize: process.env.HTTPSYS_BUFFER_SIZE || 4096,
    callback: function (args) {
        var server = servers[args.requestQueue];
        if (server)
            return server._dispatch(args);
        else
            throw new Error('Server associated with HTTP.SYS request queue ' 
                + args.requestQueue + ' does not exist.');
    }
});

function ServerRequest(args, requestContext) {
    events.EventEmitter.call(this);
    this._requestContext = requestContext;
    for (var i in args.req) {
        this[i] = args.req[i];
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
};

function Server() {
    events.EventEmitter.call(this);
    this._activeRequests = {};
}

util.inherits(Server, events.EventEmitter);

Server.prototype.listen = function (port, hostname, callback) {
    if (this._server) 
        throw new Error('The server is already listening. Call close before calling listen again.');

    if (!port || isNaN(+port))
        throw new Error('Port must be specified as a positive integer.');

    if (typeof hostname === 'function') {
        callback = hostname;
        hostname = '127.0.0.1';
    }
    else if (typeof hostname === 'undefined') {
        hostname = '127.0.0.1';
    }

    if (typeof callback === 'function') {
        this.on('listening', callback);
    }

    var options = {
        url: this._scheme + hostname + ':' + port + '/',
        pendingReadCount: process.env.on_PENDING_READ_COUNT || 1
    };

    try {
        this._nativeServer = httpsys.httpsys_listen(options);
        servers[this._nativeServer.requestQueue] = this;
    }
    catch (e) {
        throw new Error('Error initializing the HTTP.SYS server. System error ' + e + '.');
    }

    this.emit('listening');
};

Server.prototype.close = function () {
    if (this._server) {
        try {
            httpsys.httpsys_stop_listen(this._nativeServer);
        }
        catch (e) {
            throw new Error('Error closing the HTTP.SYS listener. System error ' + e + '.');
        }

        delete servers[this._nativeServer.requestQueue];
        delete this._nativeServer;
        this.emit('close');
    }
};

Server.prototype._dispatch = function (args) {
    if (!args.eventType || !nativeEvents[args.eventType])
        throw new Error('Unrecognized eventType: ' + args.eventType);

    return this[nativeEvents[args.eventType]](args);
};

Server.prototype._getRequestContext = function(args) {
    var requestContext = this._activeRequests[args.uv_httpsys];
    if (!requestContext) {
        throw new Error('JavaScript ServerRequest matching uv_httpsys handle ' 
            + args.uv_httpsys + ' not found.');
    }

    return requestContext;
};

Server.prototype._on_error_initializing_request = function(args) {
    throw args; // TPDP
};

Server.prototype._on_error_new_request = function(args) {
    throw args; // TPDP
};

Server.prototype._on_new_request = function(args) {
    var requestContext = {
        uv_httpsys: args.uv_httpsys,
        requestQueue: args.requestQueue,
        asyncPending: false,
        requestRead: false,
        server: this
    };

    requestContext.req = new ServerRequest(args, requestContext);
    requestContext.res = new ServerResponse(requestContext);
    this._activeRequests[args.uv_httpsys] = requestContext;

    this.emit('request', requestContext.req, requestContext.res);

    return !requestContext.req._paused;
};

Server.prototype._on_error_initializing_read_request_body = function(args) {
    throw args; // TPDP
};

Server.prototype._on_end_request = function(args) {
    var requestContext = this._getRequestContext(args);
    requestContext.req._on_end_request();
};

Server.prototype._on_error_read_request_body = function(args) {
    throw args; // TPDP
};

Server.prototype._on_request_body = function(args) {
    var requestContext = this._getRequestContext(args);
    requestContext.req._on_request_body(args);

    return !requestContext.req._paused;
};

Server.prototype._on_headers_written = function(args) {

};

Server.prototype._on_error_writing_headers = function(args) {
    throw args; // TPDP
};

Server.prototype._on_body_written = function(args) {

};

Server.prototype._on_error_writing_body = function(args) {
    throw args; // TPDP
};

function HttpServer() {
    Server.call(this);
    this._scheme = 'http://';
};

util.inherits(HttpServer, Server);

function ServerResponse(requestContext) {
    events.EventEmitter.call(this);
    this._requestContext = requestContext;
};

util.inherits(ServerResponse, events.EventEmitter);

exports.http = {};
exports.http.Server = HttpServer;
exports.http.ServerRequest = ServerRequest;
exports.http.ServerResponse = ServerResponse;

exports.http.createServer = function (requestListener) {
    var server = new HttpServer();
    if (requestListener) {
        server.on('request', requestListener)
    }

    return server;
};
