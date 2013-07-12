var Server = require('./Server')
    , util = require('util');

function HttpsServer() {
    Server.call(this);
    this._scheme = 'https://';
};

util.inherits(HttpsServer, Server);

module.exports = HttpsServer;
