var httpsys = require('./httpsys_native')
    , events = require('events')
    , util = require('util');

// Locally polyfill Buffer.concat for Node.js < 0.8

var bufferConcat = Buffer.concat || function (list) {
    if (list.length === 0) {
        return new Buffer(0);
    } else if (list.length === 1) {
        return list[0];
    }

    var length = 0;
    list.forEach(function (buf) { length += buf.length; });
    
    var buffer = new Buffer(length);
    var pos = 0;
    for (var i = 0; i < list.length; i++) {
      var buf = list[i];
      buf.copy(buffer, pos);
      pos += buf.length;
    }

    return buffer;
};

// Maps known HTTP response header name to HTTP_HEADER_ID enum value
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa364526(v=vs.85).aspx
var knownResponseHeaders = {
    'cache-control': 0,
    'connection': 1,
    'date': 2,
    'keep-alive': 3,
    'pragma': 4,
    'trailer': 5,
    'transfer-encoding': 6,
    'upgrade': 7,
    'via': 8,
    'warning': 9,
    'alive': 10,
    'content-length': 11,
    'content-type': 12,
    'content-encoding': 13,
    'content-language': 14,
    'content-location': 15,
    'content-md5': 16,
    'content-range': 17,
    'expires': 18,
    'last-modified': 19,
    'accept-ranges': 20,
    'age': 21,
    'etag': 22,
    'location': 23,
    'proxy-authenticate': 24,
    'retry-after': 25,
    'server': 26,
    'set-cookie': 27,
    'vary': 28,
    'www-authenticate': 29,
    'if-modified-since': 30,
    'if-none-match': 31,
    'if-range': 32,
    'if-unmodified-since': 33,
    'max-forwards': 34,
    'proxy-authorization': 35,
    'referer': 36,
    'range': 37,
    'te': 38,
    'translate': 39,
    'user-agent': 40
};

// Constants for chunked transfer encoding.
var lastChunk = new Buffer('0\x0d\x0a\x0d\x0a');
var crlf = new Buffer('\x0d\x0a');    

function Socket(requestContext) {
    events.EventEmitter.call(this);
    this._requestContext = requestContext;
    this._encoding = 'binary';

    // Prevent 'error' events without registred handlers from surfacing as 
    // uncaughtExceptions. This appears to be the case with socket.io.

    this.on('error', function () {}); 
};

util.inherits(Socket, events.EventEmitter);

Socket.prototype._writeHead = function (statusCode, reasonPhrase, headers) {
    this._ensureOpened();

    if (!statusCode || isNaN(+statusCode))
        throw new Error('Status code must be specified as a positive integer.');

    if (typeof reasonPhrase === 'object') {
        headers = reasonPhrase;
        reasonPhrase = '';
    }
    else if (reasonPhrase === null || typeof reasonPhrase === 'undefined') {
        reasonPhrase = '';
    }
    else if (typeof reasonPhrase !== 'string') 
        throw new Error('Reason phrase must be a string.');

    if (typeof headers !== 'undefined' && typeof headers !== 'object') 
        throw new Error('Headers must be an object.');

    if (this._requestContext.headersWritten) 
        throw new Error('The writeHead method cannot be called after the response headers have been sent.');

    this._requestContext.statusCode = statusCode;
    this._requestContext.reason = reasonPhrase;
    if (headers) {
        for (var i in headers)
            this._requestContext.headers[i.toLowerCase()] = headers[i].toString();
    }
};

Socket.prototype._ensureUpgradeProcessed = function() {
    // This is a response to an HTTP upgrade request. The HTTP response headers are written
    // by the Node.js application directly to the Socket as there is no response object. 
    // Here the HTTP response status line and headers need to be deserialized again, 
    // since HTTP.SYS APIs require that an upgrade response is initiated with a call to 
    // HttpSendHttpResponse before access to the raw TCP connection is granted. 

    // This method will process the chunks queued up in this._requestContext.chunks to try to parse the
    // HTTP status line and headers. If successful, the this._requestContext.{headers|statusCode|reason}
    // are set accordingly and the this._requestContext.chunks is augmented with the unparsed bytes
    // of the entity body.

    var buffer = bufferConcat(this._requestContext.chunks);
    var response = buffer.toString('utf8');
    var endOfHeaders = response.indexOf('\r\n\r\n');
    if (endOfHeaders < 0) {
        // Not all HTTP response headers have yet been written out to the socket

        return false;
    }

    // Parse status line

    var statusCode;
    var reason;
    var responseHeaders;
    var match = (/^HTTP\/\d+\.\d+\s+(\d+)[^\s]*\s+([^\r]*)\r\n/).exec(response);
    if (match) {
        statusCode = +match[1];
        reason = match[2];
        responseHeaders = response.substring(match[0].length);
    }
    else {
        throw new Error('Invalid HTTP upgrade response. Unable to parse the response status line.');
    }

    // Parse headers

    var headers = {};
    var headerRegEx = /([^\:]+)\s*\:\s*(.*)\r\n/g;
    var lastIndex = -1;
    while ((match = headerRegEx.exec(responseHeaders)) !== null) {
        headers[match[1]] = match[2];
        lastIndex = headerRegEx.lastIndex;
    }

    if (lastIndex < (endOfHeaders - response.length + responseHeaders.length)) {
        throw new Error('Invalid HTTP upgrade response. Unable to parse the response headers.');
    }

    // Set the headers and adjust the entity body to be written out

    this._requestContext.headers = headers;
    this._requestContext.statusCode = statusCode;
    this._requestContext.reason = reason;
    this._requestContext.chunks = [];
    if (buffer.length > (endOfHeaders + 4)) {
        this._requestContext.chunks.push(buffer.slice(endOfHeaders + 4));
    }

    return true;
};

Socket.prototype.write = function(chunk, encoding, isEnd) {
    this._ensureOpened();

    if (this._requestContext.upgrade) {
        // Queue up the chunk of the body to be sent.
        // For upgrade requests the chunk must be added before a call to _ensureUpgradeProcessed.
        // Regular responses cannot add the chunk here since it is not known yet whether chunking 
        // needs to be applied. 
        this._queue_body_chunk(chunk, encoding, isEnd);

        if (!this._requestContext.knownHeaders 
            && !this._requestContext.disconnect 
            && !this._ensureUpgradeProcessed()) {

            // This is a response to an upgrade request, but the application has not yet fully written out
            // the HTTP response status line and headers to the socket. Return and wait for another call to write.
            // At this point the chunk of the response has already been queued up in the requestContext.chunks.

            return false;
        }        
    }   

    if (!this._requestContext.knownHeaders) {
        // First call to write prepares the cached response headers

        // Upgrade reqeusts are never chunked. For regular requests assume chunking unless proven otherwise.
        this._requestContext.chunkResponse = !this._requestContext.upgrade;

        this._requestContext.knownHeaders = [];
        this._requestContext.unknownHeaders = {};
        for (var i in this._requestContext.headers) {
            var id = knownResponseHeaders[i];
            if (id === undefined)
                this._requestContext.unknownHeaders[i] = this._requestContext.headers[i];
            else {
                this._requestContext.knownHeaders.push({id: id, value: this._requestContext.headers[i]});
                if (6 === id || 11 === id) {
                    // Either Content-Length or Transfer-Encoding headers were specified,
                    // chunked transfer encoding need not be applied.
                    this._requestContext.chunkResponse = false;
                }
            }
                
        }

        // Determine if chunked transfer encoding must be applied.

        if (this._requestContext.chunkResponse) {
            // Add Transfer-Encoding: chunked header if chunking will be applied.

            this._requestContext.knownHeaders.push({id: 6, value: 'chunked'});
        }
    }

    // propagate cacheDuration from ServerResponse to _requestContext if it was set

    if (!isNaN(this.cacheDuration)) {
        this._requestContext.cacheDuration = this.cacheDuration;
    }

    if (!this._requestContext.upgrade) {
        // Queue up the chunk of the body to be sent after headers have been sent.
        // For upgrade requests the chunk had already been added at the beginning of this function.
        this._queue_body_chunk(chunk, encoding, isEnd);
    }    

    return this._initiate_send_next();
};

Socket.prototype.end = function (chunk, encoding) {
    if (chunk) {
        this._ensureOpened();
        return this.write(chunk, encoding, true);
    }
    else if (!this._closed) {
        return this.write(chunk, encoding, true);   
    }
    else {
        return true;
    }
};

Socket.prototype._setHeader = function (name, value) {
    this._ensureOpened();

    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    if (Array.isArray(value)) 
        throw new Error('Array header values are not supported. The HTTP header value must be atomic.');

    if (typeof value !== 'string')
        value += '';

    // TODO: support for multiple headers with the same name

    if (this._requestContext.knownHeaders)
        throw new Error('Response headers cannot be modified after they have been sent to the client.');

    this._requestContext.headers[name.toLowerCase()] = value.toString();
};

Socket.prototype._getHeader = function (name) {
    this._ensureOpened();

    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    return this._requestContext.headers[name.toLowerCase()];    
};

Socket.prototype._removeHeader = function (name) {
    this._ensureOpened();

    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    if (this._requestContext.knownHeaders)
        throw new Error('Response headers cannot be modified after they have been sent to the client.');

    return delete this._requestContext.headers[name.toLowerCase()];    
};

Socket.prototype._queue_body_chunk = function (chunk, encoding, isEnd)
{
    this._ensureOpened();

    if (this._requestContext.isLastChunk)
        throw new Error('No more response data can be written after the end method had been called.');

    if (!Buffer.isBuffer(chunk)) {
        if (typeof chunk === 'string') {
            chunk = new Buffer(chunk, encoding || 'utf8');
        }
        else if (chunk === null && isEnd !== true) {
            throw new Error('Chunk must be a string or a Buffer.');
        }
    }

    if (!this._requestContext.chunks)
        this._requestContext.chunks = [];

    if (chunk) {
        if (this._requestContext.chunkResponse)
            this._requestContext.chunks.push(
                new Buffer(chunk.length.toString(16) + '\x0d\x0a'),
                chunk,
                crlf);
        else
            this._requestContext.chunks.push(chunk);
    }

    if (isEnd) {
        this._requestContext.isLastChunk = true;
        if (this._requestContext.chunkResponse)
            this._requestContext.chunks.push(lastChunk);
    }
};

Socket.prototype._on_written = function () {
    if (this._requestContext.drainEventPending && !this._requestContext.chunks) {
        delete this._requestContext.drainEventPending;
        if (!this._closed) {
            this.emit('drain');
        }
    }

    if (!this._closed && this._requestContext.chunks)
        this._initiate_send_next();
};

Socket.prototype._initiate_send_next = function () {
    this._ensureOpened();

    if (this._requestContext.asyncPending('res')) {
        // Another response async operation is pending.
        // Postpone send until entire request had been read and no async operations are pending. 

        if (this._requestContext.chunks) {
            // There is a chunk of the body to be sent, but it cannot be sent synchronously.
            // The 'drain' event must therefore be emitted once the chunk is sent in the future. 

            this._requestContext.drainEventPending = true;
        }

        return false;
    }

    if (this._requestContext.knownHeaders && !this._requestContext.headersWritten) {
        // Initiate sending HTTP response headers and body, if any. 

        this._requestContext.headersWritten = true;

        try {
            this._requestContext.asyncPending('res', httpsys.httpsys_write_headers(this._requestContext));
        }
        catch (e) {
            this._error('res', e);
        }

        if (!this._requestContext.asyncPending('res') && !this._requestContext.disconnect) {
            // Synchronous completion
            this._on_written();
        }

        return true;
    }
    else if (this._requestContext.chunks) {
        // Initiate sending HTTP response body.

        try {
            this._requestContext.asyncPending('res', httpsys.httpsys_write_body(this._requestContext));
        }
        catch (e) {
            this._error('res', e);
        }
        
        if (!this._requestContext.asyncPending('res') && !this._requestContext.disconnect) {
            // Synchronous completion
            this._on_written();
        }

        return true;
    }

    return false;
};

Socket.prototype.pause = function () {
    this._ensureOpened();

    this._paused = true;
};

Socket.prototype.resume = function () {
    this._ensureOpened();

    if (this._paused) {
        if (!this._requestContext.asyncPending('req')) {
            httpsys.httpsys_resume(this._requestContext);
        }

        delete this._paused;
    }
};

Socket.prototype.setEncoding = function (encoding) {
    this._encoding = encoding || 'utf8';
};

Socket.prototype._on_request_body = function (args) {
    if (!this._closed) {
        if (this._requestContext.responseStarted) {
            // If response was started by the application asynchronously (e.g from
            // setTimeout or other async callback) while a read request was pending,
            // continue to sending the response without emitting the 'data' event.

            this._initiate_send_next();
        }
        else if (this._encoding === 'binary') {
            this.emit('data', args.data);
        }
        else {
            this.emit('data', args.data.toString(this._encoding));
        }
    }
};

Socket.prototype._on_end_request = function () {
    if (!this._closed) {
        if (!this._requestContext.responseStarted) {
            // Only emit the 'end' event if no response was started by the application 
            // asynchronously (e.g from setTimeout or other async callback) while a read 
            // request was pending.

            this.emit('end');
        }        

        // Signal the response to start sending cached response content if any
        // had been accumulated while the response was being received.

        this._initiate_send_next();
    }
};

Socket.prototype.setTimeout = function (timeout, callback) {
    // TODO: implement full Socket.setTimeout semantics 
    // http://nodejs.org/api/net.html#net_socket_settimeout_timeout_callback

    if (timeout !== 0) {
        throw new Error('Not implemented. Only timeout value of 0 is currently accepted.')
    }
};

Socket.prototype.setNoDelay = function (noDelay) {
    this._requestContext.noDelay = typeof noDelay === 'boolean' ? noDelay : true;
};

Socket.prototype._error = function (source, error) {
    this._requestContext.asyncPending(source, false);
    if (!this._closed && !this._closing) {
        this._closing = true;
        try {
            // Ensure that all native resources are released.

            this.destroy();
        }
        catch (e) {
            // Ignore.
        }

        this._closed = true;
        this._closeError = error;
        this.emit('error', error);
        this.emit('close', true);    
    }
};

Socket.prototype._ensureOpened = function () {
    if (this._closed) {
        throw new Error('Socket is closed.')
    }
};

Socket.prototype.destroy = function () {
    if (!this._closed) {

        // Destroying a socket is implemented by calling HTTP.SYS APIs with 
        // the HTTP_SEND_RESPONSE_FLAG_DISCONNECT flag. There are two scenarios: 
        // 1. HTTP response headers were not sent yet. In this case calling end() below will cause 
        //    the response headers with the disconnect flag to be sent.
        // 2. HTTP reasponse headers were already sent. In this case calling end() below will cause
        //    an empty entity body with the disconnect flag to be sent.
        // In both cases native resources will be cleaned up. 

        if (!this._requestContext.knownHeaders) {
            this._requestContext.statusCode = 400;
        }

        this._requestContext.disconnect = true;

        if (!this._requestContext.isLastChunk) {
            // Only call end if it was not called before
            this.end();
        }

        if (!this._closed && !this.closing) {
            // this._closed can be true if the end() completed synchronously
            // this._closing is true if the socket._error was called and the socket is being destroyed
            this._closed = true;
            this.emit('close', false);
        }
    }
};

module.exports = Socket;
