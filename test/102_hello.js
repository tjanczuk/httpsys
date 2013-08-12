var http = require('../lib/httpsys.js').http()
    , https = require('../lib/httpsys.js').https()
    , fs = require('fs')
    , assert = require('assert');

var port = process.env.PORT || 3102;
var sslport = process.env.SSLPORT || 3103;
var server;
var serverCert = fs.readFileSync(__dirname + '\\..\\performance\\x509-sha1.pem');

describe('102_hello.js: hello, world', function () {

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

    it('works with HTTP', function (done) {
        server = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 1!');
        });

        server.listen(port);

        sendHello('Hello, world 1!', false, done);
    });

    it('works with HTTP after reopen', function (done) {
        server = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 2!');
        });

        server.listen(port);

        sendHello('Hello, world 2!', false, done);
    });    

    it('works with HTTPS', function (done) {
        server = https.createServer({}, function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 3!');
        });

        server.listen(sslport);

        sendHello('Hello, world 3!', true, done);
    });

    it('works with HTTPS after reopen', function (done) {
        server = https.createServer({}, function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 4!');
        });

        server.listen(sslport);

        sendHello('Hello, world 4!', true, done);
    });    

});

function sendHello(hello, secure, done) {
    var options = {
        hostname: 'localhost',
        port: (secure ? sslport : port),
        path: '/',
        method: 'GET',
        // when SSL is used, reject all server certificates except the one used in the test:
        agent: false,
        rejectUnauthorized: true, 
        ca: [ serverCert ]
    };

    var request = (secure ? https : http).request(options, function (res) {
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['content-type'], 'text/plain');
        var body = '';
        res.on('data', function (chunk) { body += chunk; });
        res.on('end', function () {
            assert.equal(body, hello);
            done();
        });
    });

    request.on('error', assert.ifError);
    request.end();    
}