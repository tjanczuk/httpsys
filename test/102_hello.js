var http = require('../lib/httpsys.js').http()
	, assert = require('assert');

var port = process.env.PORT || 3000;

describe('hello, world', function () {

	it('works', function (done) {
		var server = http.createServer(function (req, res) {
			res.writeHead(200, { 'Content-Type': 'text/plain' });
			res.end('Hello, world!');
		});

		server.listen(port);

		var request = http.get('http://localhost:' + port, function (res) {
			assert.equal(res.statusCode, 200);
			assert.equal(res.headers['content-type'], 'text/plain');
			var body = '';
			res.on('data', function (chunk) { body += chunk; });
			res.on('end', function () {
				assert.equal(body, 'Hello, world!');
				done();
			})
		});

		request.on('error', function (e) {
			assert.ifError(e);
		});
	});

});