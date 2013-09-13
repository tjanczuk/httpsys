var http = require('../lib/httpsys.js').http()
    , https = require('../lib/httpsys.js').https()
    , socketio = require('socket.io')
    , socketio_client = require('socket.io-client')
    , assert = require('assert');

var port = process.env.PORT || 3401;
var sslport = process.env.PORT || 3421;
var server;

// Enable node.js v0.10 to accept self-signed X.509 server certificates as per
// http://stackoverflow.com/questions/15365772/socket-io-ssl-self-signed-ca-certificate-gives-error-when-connecting
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('401_socketio.js: socket.io', function () {

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
        testTransport('websocket', false, done);
    });

    it('works with HTTP', function (done) {
        testTransport('xhr-polling', false, done);
    });    

    it('works with WSS', function (done) {
        testTransport('websocket', true, done);
    });

    it('works with HTTPS', function (done) {
        testTransport('xhr-polling', true, done);
    });      

    function testTransport(transport, secure, done) {
        if (secure) {
            server = https.createServer({}, function (req, res) {
                throw new Error('Regular HTTPS request detected.');
            });
        }
        else {
            server = http.createServer(function (req, res) {
                throw new Error('Regular HTTP request detected.');
            });
        }

        var wss = socketio.listen(server, { log: false });
        var refCount = 2;

        wss.configure(function() {
            wss.set('transports', [ transport ]);
        });

        var serverLog = [];
        var clientLog = [];
        var toSend = ['one', 'two', 'three', 'four'];

        wss.sockets.on('connection', function(ws) {
            serverLog.push('connection');
            ws.on('message', function(message) {
                serverLog.push(message);
                ws.emit('message', message.toUpperCase());
            }).on('disconnect', function (reason) {
                serverLog.push('disconnect');
                validate();
            });
        });

        if (secure) {
            server.listen(sslport);
            var ws = socketio_client.connect('https://localhost:' + sslport);
            sslport++; // for subsequent tests
        }
        else {
            server.listen(port);
            var ws = socketio_client.connect('http://localhost:' + port);
            port++; // for subsequent tests
        }

        ws.on('connect', function() {
            clientLog.push('connect');
            sendNext();
        }).on('message', function(message) {
            clientLog.push(message);
            sendNext();
        }).on('disconnect', function (reason) {
            clientLog.push('disconnect');        
            validate();    
        });

        function sendNext() {
            var next = toSend.shift();
            next ? ws.emit('message', next) : ws.disconnect();
        }

        function validate() {
            if (--refCount === 0) {
                assert.deepEqual(serverLog, [ 'connection', 'one', 'two', 'three', 'four', 'disconnect' ]);
                assert.deepEqual(clientLog, [ 'connect', 'ONE', 'TWO', 'THREE', 'FOUR', 'disconnect' ]);
                done();
            }
        }        
    }

});