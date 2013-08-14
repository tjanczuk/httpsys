var versionMap = [
    [ /^0\.6\./, '0.6.20' ],
    [ /^0\.8\./, '0.8.22' ],
    [ /^0\.10\./, '0.10.15' ]
];

function determineVersion() {
    for (var i in versionMap) {
        if (process.versions.node.match(versionMap[i][0])) {
            return versionMap[i][1];
        }
    }

    throw new Error('The httpsys module has not been pre-compiled for node.js version ' + process.version +
        '. You must build a custom version of httpsys.node. Please refer to https://github.com/tjanczuk/httpsys ' +
        'for building instructions.');
}

if (process.env.HTTPSYS_NATIVE) {
    exports = module.exports = require(process.env.HTTPSYS_NATIVE);
}
else if (process.platform === 'win32') {
    exports = module.exports = require('./native/' + process.platform + '/' 
        + process.arch + '/' + determineVersion() + '/httpsys');
}
else {
    throw new Error('The httpsys module is only supported on Windows.');
}    

// Currently active HTTP[S] servers (Server instances), keyed by HTTP.SYS's request queue ID
exports.servers = {};

// Running counter of servers that acts as a unique server Id
exports.serverId = 1;

// This is a v-table mapping event types defined by uv_httpsys_event_type in httpsys.h
// to action methods. This is used in Server.prototype._dispatch.
// Order is important and must match uv_httpsys_event_type.
exports.nativeEvents = [
    undefined,                        // 0 - unused
    '_on_error_initializing_request', // 1
    '_on_error_new_request',          // 2
    '_on_new_request',                // 3
    '_on_error_initializing_read_request_body', // 4 
    '_on_end_request',                          // 5
    '_on_error_read_request_body',              // 6
    '_on_request_body',                         // 7
    '_on_written',                              // 8
    '_on_error_writing',                        // 9
    '_on_server_closed'                         // 10
];
