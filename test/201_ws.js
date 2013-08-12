var http = require('../lib/httpsys.js').http()
    , https = require('../lib/httpsys.js').https()
    , WebSocket = require('ws')
    , WebSocketServer = require('ws').Server
    , fs = require('fs')
    , assert = require('assert');

var port = process.env.PORT || 3201;
var sslport = process.env.PORT || 3202;
var server;
var serverCert = fs.readFileSync(__dirname + '\\..\\performance\\x509-sha1.pem');

describe('201_ws.js: einaros/ws', function () {

    afterEach(function (done) {
        if (server) {
            server.close(function () {
                done();
                server = undefined;
            });
        }
        else {
            done();
        }
    });

    it('works with WS', function (done) {
        test(false, done);
    });

    it('works with WSS', function (done) {
        test(true, done);
    });

    function test(secure, done) {
        if (secure) {
            server = https.createServer({}, function (req, res) {
                throw new Error('Regular HTTPS request detected.');
            }).listen(sslport);
        }
        else {
            server = http.createServer(function (req, res) {
                throw new Error('Regular HTTP request detected.');
            }).listen(port);
        }

        var wss = new WebSocketServer({ server: server });
        var serverLog = [];
        var clientLog = [];
        var toSend = ['one', 'two', 'three', 'four'];
        var refCount = 2;

        wss.on('connection', function(ws) {
            serverLog.push('connection');
            ws.on('message', function(message) {
                serverLog.push(message);
                ws.send(message.toUpperCase());
            }).on('close', function () {
                serverLog.push('close');
                validate();
            }).on('error', assert.ifError);
        }).on('error', assert.ifError);

        var ws;

        if (secure) {
            // when SSL is used, reject all server certificates except the one used in the test:
            ws = new WebSocket('wss://localhost:' + sslport + '/', {
                agent: false,
                rejectUnauthorized: true, 
                ca: [ serverCert ]
            });
        }
        else {
            ws = new WebSocket('ws://localhost:' + port + '/');
        }
        
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
            if (--refCount === 0) {
                assert.deepEqual(serverLog, [ 'connection', 'one', 'two', 'three', 'four', 'close' ]);
                assert.deepEqual(clientLog, [ 'open', 'ONE', 'TWO', 'THREE', 'FOUR', 'close' ]);
                done();
            }
        }        
    }

});