var http = require('../lib/httpsys').http();

http.createServer(function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello from ' + process.pid);
}).listen('http://*:8080/bar/');