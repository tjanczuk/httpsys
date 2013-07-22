var http = require('../lib/httpsys.js').http()
    , assert = require('assert');

var port = process.env.PORT || 3102;
var server;

describe('hello, world', function () {

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

    it('works', function (done) {
        server = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 1!');
        });

        server.listen(port);

        sendHello('Hello, world 1!', done);
    });

    it('works after reopen', function (done) {
        server = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world 2!');
        });

        server.listen(port);

        sendHello('Hello, world 2!', done);
    });    

});

function sendHello(hello, done) {
    var request = http.request({
        hostname: 'localhost',
        port: port,
        path: '/',
        method: 'GET'
    }, function (res) {
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