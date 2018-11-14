//allow self signed certificates
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var http = require('../index').http()
    , https = require('../index').https()
    , socketio = require('socket.io')
    , socketio_client = require('socket.io-client')
    , fs = require('fs')    
    , assert = require('assert');

var domain = "http://localhost";
var port = process.env.PORT || 3401;
var sslport = process.env.PORT || 3421;

var server;
var serverCert = fs.readFileSync(__dirname + '\\..\\performance\\x509-sha1.pem');

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
        testTransport('polling', false, done);
    });    

    it('works with WSS', function (done) {
        testTransport('websocket', true, done);
    });

    it('works with HTTPS', function (done) {
        testTransport('polling', true, done);
    });      

    function testTransport(transport, secure, done) {

        //create and listen on sever port
        if (secure) {
            server = https.createServer({}, function (req, res) {
                throw new Error('Regular HTTPS request detected.');
            });

            server.on('error', function (err) {
                throw new Error('failed to listen on ' + sslport);
            }).listen(domain + ":" + sslport + "/", function () {
                //console.log('listening on ' + sslport);
            });
        }
        else {
            server = http.createServer(function (req, res) {
                throw new Error('Regular HTTP request detected.');
            });

            server.on('error', function (err) {
                throw new Error('failed to listen on ' + port);
            }).listen(domain + ":" + port + "/", function () {

            });
        }

        //configure socketio to listen on server port
        var wss = socketio.listen(server, { log: false });
        var refCount = 2;

        var serverLog = [];
        var clientLog = [];
        var toSend = ['one', 'two', 'three', 'four'];

        //configure socketio server event listeners
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

        //perform client connection to listening server
        if (secure) {
            var ws = socketio_client.connect(domain + ":" + sslport);
            sslport++; // for subsequent tests            
        }
        else {
            var ws = socketio_client.connect(domain + ":" + port);
            port++; // for subsequent tests            
        }

        //configure socketio client event listeners
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