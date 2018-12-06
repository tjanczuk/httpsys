var version = require('./package.json').version
    , httpsys = require('./lib/httpsys_native')
    , HttpServer = require('./lib/HttpServer')
    , HttpsServer = require('./lib/HttpsServer')
    , Server = require('./lib/Server')
    , ServerRequest = require('./lib/ServerRequest')
    , ServerResponse = require('./lib/ServerResponse')
    , util = require('util');

httpsys.httpsys_init({
    initialBufferSize: (+process.env.HTTPSYS_BUFFER_SIZE) || 16384,
    requestQueueLength: (+process.env.HTTPSYS_REQUEST_QUEUE_LENGTH) || 5000,
    pendingReadCount: (+process.env.HTTPSYS_PENDING_READ_COUNT) || 1,
    cacheDuration: isNaN(process.env.HTTPSYS_CACHE_DURATION) ? -1 : (+process.env.HTTPSYS_CACHE_DURATION),
    callback: Server._dispatch
});

function addClientStack(target, source) {
    [   'STATUS_CODES',
        'IncomingMessage',
        'OutgoingMessage',
        'Agent',
        'globalAgent',
        'ClientRequest',
        'request',
        'get',
        'Client',
        'createClient'
    ].forEach(function (api) {
        if (source[api])
            target[api] = source[api];
    });
}

var http;
var https;

exports.http = function () {
    if (!http) {
        http = {
            Server: HttpServer,
            ServerRequest: ServerRequest,
            ServerResponse: ServerResponse,
            createServer: function (requestListener) {
                var server = new HttpServer();
                if (requestListener) {
                    server.on('request', requestListener)
                }

                return server;
            },
            httpsys_version: version
        };

        addClientStack(http, require('http'));
    }

    return http;
};

exports.https = function () {
    if (!https) {
        https = {
            Server: HttpsServer,
            createServer: function (options, requestListener) {

                // `options` are ignored for API compatibility 
                // Keys and certificates in HTTP.SYS
                // are configured with `netsh http add sslcert`.

                var server = new HttpsServer();
                if (requestListener) {
                    server.on('request', requestListener)
                }

                return server;
            },
            httpsys_version: version
        };

        addClientStack(https, require('https'));
    }

    return https;
}

exports.http.slipstream = function () {
    // Make sure original HTTP module is loaded into native module cache
    module = require('http');
    module.createServer = function (requestListener) {
        var server = new HttpServer();
        if (requestListener) {
            server.on('request', requestListener)
        }
        return server;
    }
    
    module.Server = HttpServer;
    module.ServerRequest = ServerRequest;
    module.ServerResponse = ServerResponse;
    module.httpsys_version = version;
};

exports.https.slipstream = function() {
    // Make sure original HTTPS module is loaded into native module cache
    module = require('https');
    
    module.Server = HttpsServer;
    module.createServer = function (options, requestListener) {
        // `options` are ignored for API compatibility 
        // Keys and certificates in HTTP.SYS
        // are configured with `netsh http add sslcert`.
        var server = new HttpsServer();
        if (requestListener) {
            server.on('request', requestListener)
        }
        return server;
    };

    module.httpsys_version = version;
};

exports.slipstream = function () {
    exports.http.slipstream();
    exports.https.slipstream();
};
