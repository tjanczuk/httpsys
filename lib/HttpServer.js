var Server = require('./Server')
    , util = require('util');

function HttpServer() {
    Server.call(this);
    this._scheme = 'http://';
};

util.inherits(HttpServer, Server);

module.exports = HttpServer;
