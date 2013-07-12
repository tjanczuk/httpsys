var httpsys = require('./httpsys_native')
    , HttpServer = require('./HttpServer')
    , HttpsServer = require('./HttpsServer')
    , ServerRequest = require('./ServerRequest')
    , ServerResponse = require('./ServerResponse');

httpsys.httpsys_init({
    initialBufferSize: (+process.env.HTTPSYS_BUFFER_SIZE) || 4096,
    requestQueueLength: (+process.env.HTTPSYS_REQUEST_QUEUE_LENGTH) || 5000,
    pendingReadCount: (+process.env.HTTPSYS_PENDING_READ_COUNT) || 1,
    cacheDuration: isNaN(process.env.HTTPSYS_CACHE_DURATION) ? -1 : (+process.env.HTTPSYS_CACHE_DURATION),
    callback: function (args) {
        var server = httpsys.servers[args.uv_httpsys_server.serverId];
        if (server)
            return server._dispatch(args);
        else
            throw new Error('Server associated with HTTP.SYS request queue ' 
                + args.uv_httpsys_server.serverId + ' does not exist.');
    }
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
            }
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
            }
        };

        addClientStack(https, require('https'));
    }

    return https;
}
