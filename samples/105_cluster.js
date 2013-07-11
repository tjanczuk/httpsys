var http = require('../lib/httpsys').http();
var cluster = require('cluster');
var numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
    console.log('Setting up cluster with ' + numCPUs + ' processes'); 

    for (var i = 0; i < numCPUs; i++) {
        cluster.fork(process.env);
    }

    cluster.on('exit', function(worker, code, signal) {
        console.log('worker ' + worker.process.pid + ' died');
    });
}
else {
    http.createServer(function (req, res) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello from ' + process.pid);
    }).listen(8080);
}
