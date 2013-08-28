var https = require('../lib/httpsys.js').https()
    , fs = require('fs')
    , assert = require('assert');

var sslport = process.env.SSLPORT || 3501;
var server;
var serverCert = fs.readFileSync(__dirname + '\\..\\performance\\x509-sha1.pem');
var clientCert = fs.readFileSync(__dirname + '\\..\\performance\\x509-sha1-client.pem');

describe('501_https_mutual.js: SSL mutual X.509 authentication', function () {

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

    it('works with valid client certificate', function (done) {
        server = https.createServer({}, function (req, res) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                message: 'Hello, world 1!',
                client: {
                    authorized: req.client.authorized,
                    authorizationError: req.client.authorizationError,
                    cert: req.client.getPeerCertificate()
                }
            }));
        });

        server.listen(sslport);

        sendHello(clientCert, function (req) {
            assert.equal('Hello, world 1!', req.message);
            assert.equal(true, req.client.authorized);
            assert.equal(undefined, req.client.authorizationError);
            assert.equal('object', typeof req.client.cert);
            assert.equal('CN=httpsys-client', req.client.cert.subject);
            assert.equal('CN=httpsys-client', req.client.cert.issuer);
            assert.equal('Tue, 27 Aug 2013 22:22:20 GMT', req.client.cert.valid_from);
            assert.equal('Thu, 01 Jan 2099 07:00:00 GMT', req.client.cert.valid_to);
            assert.equal('54:71:3D:E8:56:FB:5D:4E:AE:DE:C9:E4:E7:A3:54:F5:DA:02:EF:EF', req.client.cert.fingerprint);
            done();
        });
    });

    it('fails with bad usage client certificate', function (done) {
        server = https.createServer({}, function (req, res) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                message: 'Hello, world 2!',
                client: {
                    authorized: req.client.authorized,
                    authorizationError: req.client.authorizationError,
                    cert: req.client.getPeerCertificate()
                }
            }));
        });

        server.listen(sslport);

        sendHello(serverCert, function (req) {
            assert.equal('Hello, world 2!', req.message);
            assert.equal(false, req.client.authorized);
            assert.equal('CERT_E_WRONG_USAGE', req.client.authorizationError);
            assert.equal('object', typeof req.client.cert);
            assert.equal('CN=localhost', req.client.cert.subject);
            assert.equal('CN=localhost', req.client.cert.issuer);
            assert.equal('Mon, 12 Aug 2013 14:23:23 GMT', req.client.cert.valid_from);
            assert.equal('Wed, 31 Dec 2098 22:00:00 GMT', req.client.cert.valid_to);
            assert.equal('C0:8E:29:A6:96:CC:C5:A2:5E:2F:3B:9A:94:34:EA:62:4B:83:7E:E8', req.client.cert.fingerprint);
            done();
        });
    });    

});

function sendHello(cert, done) {
    var options = {
        hostname: 'localhost',
        port: sslport,
        path: '/',
        method: 'GET',
        // when SSL is used, reject all server certificates except the one used in the test:
        agent: false,
        rejectUnauthorized: true, 
        ca: [ serverCert ],
        // client auth
        key: cert,
        cert: cert        
    };

    var request = https.request(options, function (res) {
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['content-type'], 'application/json');
        var body = '';
        res.on('data', function (chunk) { body += chunk; });
        res.on('end', function () {
            done(JSON.parse(body));
        });
    });

    request.on('error', assert.ifError);
    request.end();    
}