var http = require('../lib/httpsys.js').http()
    , WebSocket = require('ws')
    , WebSocketServer = require('ws').Server
    , assert = require('assert');

var port = process.env.PORT || 3201;
var server;

describe('einaros/ws', function () {

    afterEach(function (done) {
        if (server) {
            server.close();
            server = undefined;
        }

        done();
    });

    it('works', function (done) {
        server = http.createServer(function (req, res) {
            throw new Error('Regular HTTP request detected.');
        }).listen(port);

        var wss = new WebSocketServer({ server: server });
        var serverLog = [];
        var clientLog = [];
        var toSend = ['one', 'two', 'three', 'four'];

        wss.on('connection', function(ws) {
            serverLog.push('connection');
            ws.on('message', function(message) {
                serverLog.push(message);
                ws.send(message.toUpperCase());
            }).on('close', function () {
                serverLog.push('close');
            }).on('error', assert.ifError);
        }).on('error', assert.ifError);

        var ws = new WebSocket('ws://localhost:' + port + '/');

        ws.on('open', function() {
            clientLog.push('open');
            sendNext();
        }).on('message', function(message) {
            clientLog.push(message);
            sendNext();
        }).on('close', function (e) {
            clientLog.push('close');
            validate();
        }).on('error', assert.ifError);

        function sendNext() {
            var next = toSend.shift();
            next ? ws.send(next) : ws.close();
        }

        function validate() {
            assert.deepEqual(serverLog, [ 'connection', 'one', 'two', 'three', 'four', 'close' ]);
            assert.deepEqual(clientLog, [ 'open', 'ONE', 'TWO', 'THREE', 'FOUR', 'close' ]);
            done();
        }
    });

});