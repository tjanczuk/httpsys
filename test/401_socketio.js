var http = require('../lib/httpsys.js').http()
    , socketio = require('socket.io')
    , socketio_client = require('socket.io-client')
    , assert = require('assert');

var port = process.env.PORT || 3401;
var server;

describe('socket.io', function () {

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

    it('works with websocket transport', function (done) {
        testTransport('websocket', done);
    });

    it('works with xhr-polling transport', function (done) {
        testTransport('xhr-polling', done);
    });    

    function testTransport(transport, done) {
        server = http.createServer(function (req, res) {
            throw new Error('Regular HTTP request detected.');
        });

        var wss = socketio.listen(server, { log: false });

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
                serverLog.push('disconnect', reason);
                validate();
            });
        });

        server.listen(port);

        var ws = socketio_client.connect('http://localhost:' + port);
        port++; // for subsequent tests

        ws.on('connect', function() {
            clientLog.push('connect');
            sendNext();
        }).on('message', function(message) {
            clientLog.push(message);
            sendNext();
        }).on('disconnect', function (reason) {
            clientLog.push('disconnect', reason);            
        });

        function sendNext() {
            var next = toSend.shift();
            next ? ws.emit('message', next) : ws.disconnect();
        }

        function validate() {
            assert.deepEqual(serverLog, [ 'connection', 'one', 'two', 'three', 'four', 'disconnect', 'booted' ]);
            assert.deepEqual(clientLog, [ 'connect', 'ONE', 'TWO', 'THREE', 'FOUR', 'disconnect', 'booted' ]);
            done();
        }        
    }

});