/* 
    This is test server for measuring performance.
    Configuration is controlled with environment variables:

    HTTPSYS         - if set, the HTTP.SYS stack is used; 
                      otherwise the native node.js HTTP stack is used

    HTTPSYS_CLUSTER - if set, a cluster is set up with the number of worker processes
                      equal to the number of CPUs; otherwise a one process server is set up
*/

var http = process.env.HTTPSYS ? require(__dirname + '/../../lib/httpsys.js').http() : require('http');

function createOneServer() {
    http.createServer(function (req, res) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello, world!');
    }).listen(process.env.PORT || 8080);
}

if (process.env.HTTPSYS_CLUSTER) {
    var cluster = require('cluster');
    var numCPUs = require('os').cpus().length;

    if (cluster.isMaster) {
        console.log('Setting up clustered, ' + numCPUs + ' process server ' 
	    + (process.env.HTTPSYS ? 'using HTTP.SYS...' : 'using native node.js HTTP stack...'));

        for (var i = 0; i < numCPUs; i++) {
            cluster.fork(process.env);
        }

        cluster.on('exit', function(worker, code, signal) {
            console.log('worker ' + worker.process.pid + ' died');
        });
    }
    else {
	createOneServer();
    }
}
else {
    console.log('Setting up non-cluster, one process server ' 
	+ (process.env.HTTPSYS ? 'using HTTP.SYS...' : 'using native node.js HTTP stack...'));

    createOneServer();
}
