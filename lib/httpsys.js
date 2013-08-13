// Get a reference to Node's internal NativeModule, courtesy of Brandon Benvie: 
// https://github.com/Benvie/Node.js-Ultra-REPL/blob/master/lib/ScopedModule.js
// The reference is then used in the *.slipstream methods to replace built-in
// HTTP and HTTPS modules with the HTTP.SYS one.

var NativeModule;
(function (){
    process.moduleLoadList.push = function() {
        // NativeModule.require('native_module') returns NativeModule
        NativeModule = arguments.callee.caller('native_module');

        // Delete the interceptor and re-expose normal functionality
        delete process.moduleLoadList.push;

        return Array.prototype.push.apply(process.moduleLoadList, arguments);
    };

    // Force one module resolution to enter the push method above
    require('vm');
})();

var version = require('../package.json').version
    , httpsys = require('./httpsys_native')
    , HttpServer = require('./HttpServer')
    , HttpsServer = require('./HttpsServer')
    , Server = require('./Server')
    , ServerRequest = require('./ServerRequest')
    , ServerResponse = require('./ServerResponse')
    , util = require('util');

httpsys.httpsys_init({
    initialBufferSize: (+process.env.HTTPSYS_BUFFER_SIZE) || 4096,
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

exports.http.slipstream = function() {
    // Make sure original HTTP module is loaded into native module cache
    require('http');

    // Replace the HTTP module implementation in the native module cache with HTTP.SYS
    NativeModule._cache.http.exports = exports.http();
};

exports.https.slipstream = function() {
    // Make sure original HTTPS module is loaded into native module cache
    require('https');

    // Replace the HTTPS module implementation in the native module cache with HTTP.SYS
    NativeModule._cache.https.exports = exports.https();
};

exports.slipstream = function () {
    exports.http.slipstream();
    exports.https.slipstream();
};
