var httpsys = require('./httpsys_native.js')
    , events = require('events')
    , util = require('util');

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

function ServerResponse(requestContext) {
    events.EventEmitter.call(this);
    this._requestContext = requestContext;
    this.sendDate = true;
};

util.inherits(ServerResponse, events.EventEmitter);

ServerResponse.prototype.writeHead = function (statusCode, reasonPhrase, headers) {
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
}

ServerResponse.prototype.write = function(chunk, encoding, isEnd) {
    if (!this._requestContext.headers)
        throw new Error('The writeHead method must be called before the write method.');

    if (!this._requestContext.knownHeaders) {

        // First call to write prepares the cached response headers

        this._requestContext.chunkResponse = true;

        // Process headers into known and unknown to HTTP.SYS.

        this._requestContext.knownHeaders = [];
        this._requestContext.unknownHeaders = {};
        for (var i in this._requestContext.headers) {
            var id = knownResponseHeaders[i];
            if (id === undefined)
                this._requestContext.unknownHeaders[il] = this._requestContext.headers[i];
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

    // Queue up the chunk of the body to be sent after headers have been sent.
    this._queue_body_chunk(chunk, encoding, isEnd);

    // propagate cacheDuration from ServerResponse to _requestContext if it was set

    if (!isNaN(this.cacheDuration)) {
        this._requestContext.cacheDuration = this.cacheDuration;
    }

    return this._initiate_send_next();
}

ServerResponse.prototype.end = function (chunk, encoding) {
    return this.write(chunk, encoding, true);
}

ServerResponse.prototype.writeContinue = function () {
    throw new Error('The writeContinue method is not supported because 100 Continue '
        + ' responses are sent automatically by HTTP.SYS.');
}

ServerResponse.prototype.setHeader = function (name, value) {
    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    if (!value || Array.isArray(value)) 
        throw new Error('The value paramater must be a string HTTP header value.');

    // TODO: support for multiple headers with the same name

    if (this._requestContext.knownHeaders)
        throw new Error('Response headers cannot be modified after they have been sent to the client.');

    this._requestContext.headers[name.toLowerCase()] = value.toString();
}

ServerResponse.prototype.getHeader = function (name) {
    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    if (this._requestContext.knownHeaders)
        throw new Error('Response headers cannot be accessed after they have been sent to the client.');

    return this._requestContext.headers[name.toLowerCase()];    
}

ServerResponse.prototype.removeHeader = function (name) {
    if (typeof name !== 'string')
        throw new Error('The name parameter must be a string HTTP header name.');

    if (this._requestContext.knownHeaders)
        throw new Error('Response headers cannot be modified after they have been sent to the client.');

    return delete this._requestContext.headers[name.toLowerCase()];    
}

ServerResponse.prototype.addTrailers = function () {
    // TODO support for trailers
    throw new Error('Support for trailers is not yet implemented.');
}

ServerResponse.prototype._queue_body_chunk = function (chunk, encoding, isEnd)
{
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
}

ServerResponse.prototype._on_written = function () {
    if (this._requestContext.drainEventPending && !this._requestContext.chunks) {
        delete this._requestContext.drainEventPending;
        this.emit('drain');
    }

    if (this._requestContext.chunks)
        this._initiate_send_next();
}

ServerResponse.prototype._initiate_send_next = function () {
    if (this._requestContext.asyncPending || !this._requestContext.requestRead) {
        // Another async operation is pending or the request has not been fully read yet.
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

        this._requestContext.asyncPending = httpsys.httpsys_write_headers(this._requestContext);
        if (!this._requestContext.asyncPending) {
            // Synchronous completion
            this._on_written();
        }

        return true;
    }
    else if (this._requestContext.chunks) {
        // Initiate sending HTTP response body.

        this._requestContext.asyncPending = httpsys.httpsys_write_body(this._requestContext);
        if (!this._requestContext.asyncPending) {
            // Synchronous completion
            this._on_written();
        }

        return true;
    }

    return false;
}

module.exports = ServerResponse;
