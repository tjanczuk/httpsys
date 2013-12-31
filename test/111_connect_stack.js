var http = require('../lib/httpsys.js').http()
    , https = require('../lib/httpsys.js').https()
    , fs = require('fs')
    , assert = require('assert')
    , connect = require('connect');

var port = process.env.PORT || 3102;
var server;

describe('111_connect_stack.js: connect stack integration', function () {

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

    it('works with connect.logger', function (done) {
        var log = '';
        server = http.createServer(connect()
            .use(connect.logger({
                stream: {
                    write: function(data) { log += data; }
                }
            }))
            .use(function(req, res, next) {
                res.setHeader('content-type', 'text/plain');
                if (req.url === '/test') {
                    res.statusCode = 304;
                    res.end();
                } else {
                    res.statusCode = 200;
                    res.setHeader('content-length', 14);
                    res.end('This is a test');
                }
            })
        );

        server.listen(port);

        log = '';
        sendAndCheck('/', 'hello', function(res, body) {
            assert.equal(res.statusCode, 200);
            assert.equal(res.headers['content-type'], 'text/plain');
            assert.equal(body, 'This is a test');
            assert(log.indexOf('\"GET / HTTP/1.1\" 200 14') >= 0, 'Expecting proper log message: ' + log);
            
            log = '';
            sendAndCheck('/test', '', function(res, body) {
                assert.equal(res.statusCode, 304);
                assert.equal(res.headers['content-type'], 'text/plain');
                assert.equal(body, '');
                assert(log.indexOf('\"GET /test HTTP/1.1\" 304 -') >= 0, 'Expecting proper log message: ' + log);
            
                done();
            });
        });
    });

});

function sendAndCheck(reqPath, reqBody, resCallback) {
    var options = {
        hostname: 'localhost',
        port: port,
        path: reqPath,
        method: 'GET'
    };

    var request = http.request(options, function (res) {
        var body = '';
        res.on('data', function (chunk) { body += chunk; });
        res.on('end', function () {
            resCallback(res, body);
        });
    });

    request.on('error', assert.ifError);
    request.end();    
}