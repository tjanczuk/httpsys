var https = require('httpsys').https();
var options = {};

https.createServer(options, function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!');
}).listen(8080);