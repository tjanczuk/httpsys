//var http = require('http');
var http = require('../lib/httpsys').http();

http.createServer(function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!');
}).listen(8080);