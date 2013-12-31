require('../lib/httpsys').slipstream();

var http = require('http')
    , assert = require('assert')
    , connect = require('connect')
    , fs = require('fs');

var port = process.env.PORT || 3103;
var server;

describe('110_static.js: static', function () {

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

    it('serve static file works', function (done) {
        // Create a random file, about 35KB will do
        var buf = new Buffer(35 * 1024);
        buf.fill("t");
        var fd = fs.openSync(__dirname + '/_dummy', 'w');
        fs.writeSync(fd, buf, 0, buf.length);
        fs.close(fd);
    
        // Setup server to serve static files from
        // the folder (i.e. the _dummy file we just created)
        server = http.createServer(connect()
            .use(connect.static(__dirname)));
            
        server.on('close', function() {
            fs.unlinkSync(__dirname + '/_dummy');
        });

        server.listen(port);

        var request = http.request({
            hostname: 'localhost',
            port: port,
            path: '/_dummy',
            method: 'GET'
        }, function (res) {
            // Check that we could retrieve the file
            assert.equal(res.statusCode, 200);
            assert.equal(res.headers['content-type'], 'application/octet-stream');
            var body = '';
            res.on('data', function (chunk) { body += chunk; });
            res.on('end', function () {
                assert.ok(body.indexOf('tttttttttttttt') >= 0, "Unexpected response file contents");
                done();
            });
        });

        request.on('error', assert.ifError);
        request.end();
    });

});