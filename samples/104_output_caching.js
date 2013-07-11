// set HTTPSYS_CACHE_DURATION=15
// netsh http show cachestate

var http = require('../lib/httpsys').http();

http.createServer(function (req, res) {
  console.log('Request for ' + req.url);
  res.writeHead(200, { 'Content-Type': 'text/html;charset=UTF-8' });
  // res.cacheDuration = 5; // cache this particular response for 5 seconds
  res.end('Hello, world! Time on server is ' + new Date());
}).listen(8080);