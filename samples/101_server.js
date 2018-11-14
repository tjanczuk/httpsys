//var http = require('http');
var http = require('../index').http();

http.createServer(function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!');
}).listen(8080);