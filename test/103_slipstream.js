require('../lib/httpsys').slipstream();

var http = require('http')
    , assert = require('assert');

var port = process.env.PORT || 3103;
var server;

describe('103_slipstream.js: slipstream', function () {

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

    it('works', function () {
        assert.equal(typeof http.httpsys_version, 'string');
    });

    it('hello, world works', function (done) {
        server = http.createServer(function (req, res) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('Hello, world!');
        });

        server.listen(port);

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
                assert.equal(body, 'Hello, world!');
                done();
            });
        });

        request.on('error', assert.ifError);
        request.end();
    });

});