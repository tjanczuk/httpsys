Native HTTP stack for Node.js on Windows
===

The httpsys module is a native, server side HTTP stack for Node.js applications on Windows. It is based on HTTP.SYS. 

### Benefits

Compared to the built in HTTP[S] stack in Node.js, the httpsys module offers:

* **Better performance**. Check out [early performance benchmarks](http://tomasz.janczuk.org/2012/08/the-httpsys-stack-for-nodejs-apps-on.html).  
* **Kernel mode output caching**. Applications suitable for output caching can realize additional, substantial increases in throughput. See [benchmarks](http://tomasz.janczuk.org/2012/08/the-httpsys-stack-for-nodejs-apps-on.html).  
* **Port sharing**. Horizontally partitioned applications (e.g. web chat) can use very efficient kernel mode routing to achieve process level affinity for increased throughput and reduced latency. [Read more](http://tomasz.janczuk.org/2013/05/how-to-save-5-million-running-nodejs.html).  
* **Kernel mode SSL configuration**. SSL credentials are securely configured using Windows tools rather than stored in files or provided through code. 

### Compatibility

The httpsys module requires Windows. It works with any stable version of Node.js, both 32- and 64-bit. The module was developed and tested with Node.js 0.6.20, 0.8.22, 0.10.15, each in 32 and 64 bit flavors. 

WebSockets functionality requires Windows 8 or Windows Server 2012 or later. 

The module aspires to provide high level of API and behavioral compatibility with the built in server side HTTP stack in Node.js. While it is impossible to guarantee compatibility will all Node.js applications, the httpsys module was proved to work with the cluster module, the [einaros/ws](https://github.com/einaros/ws) module for WebSockets, as well as the [socket.io](http://socket.io/) module for WebSockets and HTTP long polling. 

Any and all feedback is welcome [here](https://github.com/tjanczuk/httpsys/issues/new). Collaboration welcome - I do take contributions.

### Getting started

You must have Windows and a stable version of Node.js installed (0.6, 0.8, 0.10). Then:

```
npm install httpsys
```

Then in your code:

```javascript
// Replace the built-in HTTP[S] module with httpsys.
// This must be the first line of the app. 
require('httpsys').slipstream(); 

var http = require('http');

http.createServer(function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!');
}).listen(8080);
```

### Port sharing

To use port sharing, provide a full [URL prefix string](http://msdn.microsoft.com/en-us/library/windows/desktop/aa364698(v=vs.85\).aspx) in the call to `Server.listen`, e.g.:

```javascript
require('httpsys').slipstream(); 

var http = require('http');

http.createServer(function (req, res) {
  // ...
}).listen('http://*:8080/foo/');
```

At the same time, you can start another node.exe process that listens on a different URL prefix on the same port, e.g. `http://*:8080/bar/`. Each of the processes will only receive requests matching the URL prefix they registered for. The processes may belong to different users. 

Port sharing is particularly relevant to horizontally partitioned applications (e.g. web chat). With it you can use very efficient kernel mode routing to achieve process level affinity for increased throughput and reduced latency. [Read more](http://tomasz.janczuk.org/2013/05/how-to-save-5-million-running-nodejs.html).  

### HTTPS

Create a self-signed X.509 server certificate with associated private key and place it in the LocalMachine\My certificate store:

```
makecert -sr LocalMachine -ss My -pe -n "CN=mydomain.com" -a sha256 -len 1024 -r
```

List the certificates in the LocalMachine\My certificate store, locate the one you just created (CN=mydomain.com), and take note of its SHA1 Thumbprint: 

```
certmgr -c -s -r LocalMachine My
```

Let's assume the SHA1 Thumprint of the certificate is `EC2F8BD2 360C6118 0C0DA68C 2DC911EB 6708B1E5`. Next, register this certificate to be used by HTTP.SYS for all connections made on the TCP port on which you intend to set up the HTTPS server, in this case port 8080:

```
netsh http add sslcert ipport=0.0.0.0:8080 certhash=EC2F8BD2360C61180C0DA68C2DC911EB6708B1E5 
      appid={00112233-4455-6677-8899-AABBCCDDEEFE}
```

(line breaks added for readability only; note that you must remove spaces from the SHA1 Thumprint; the appid parameter is an arbitrary GUID).

Verify the certificate is properly installed:

```
netsh http show sslcert ipport=0.0.0.0:8080
```

Finally, author your HTTPS server:

```javascript
require('httpsys').slipstream(); 

var https = require('http');
var options = {};

https.createServer(options, function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello, world!');
}).listen(8080);
```

Note that the X.509 credentials had already been configured with HTTP.SYS, so there is no need to specify them through the `options` object passed to the `createServer`. If you do specify X.509 credentials there, they will be silently ignored. The `options` object is expected merely for API compatibility with the built-in Node.js HTTPS stack. 

Now, visit your endpoint by going to `https://localhost:8080`. The browser will display a warning given that the certificate is self-signed and therefore not trusted, but otherwise your server is fully functional. 

To inspect or modify HTTP.SYS configuration underlying your server use the `netsh http` command in Windows. This allows you to set various timeout values as well as configure SSL certificates. 

### HTTPS mutual X.509 authentication

You can configure httpsys module to require and validate client X.509 certificate. Unlike with the built-in `https` module, trust verification checks of the client certificate are configured at the operating system level using the certificate store and the `netsh` tool rather than with the `options` object passed to the `https.createServer` method. 

All SSL and cryptographic properties specified within the `options` object passed to `https.createServer` function are ignored. In partcular, none of the `options.ca`, `options.rejectUnauthorized`, and `options.requestCert` are effective. 

To require the client to present an X.509 certificate during SSL handshake, you must configure the HTTP.SYS accordingly when registering the server certificate for a particlar TCP port, e.g.:

```text
netsh http add sslcert ipport=0.0.0.0:3501 certhash=EC2F8BD2360C61180C0DA68C2DC911EB6708B1E5 
      appid={00112233-4455-6677-8899-AABBCCDDEEFE} clientcertnegotiation=enable
```

(Note the `clientcertnegotiation=enable` setting).

By default HTTP.SYS will validate client certificates by attempting to build a certificate chain up to a trusted root using the LocalMachine certificate store. You control your trust base by controlling the content of that certificate store using tools like `certmgr`, `certutil`, or the certificate plug-in for `mmc`. In addition, the `netsh http add sslcert` command allows you to fine tune the client certificate validation behavior for a particular TCP port. 

The httpsys module never automatically rejects HTTPS request when the client presents an invalid or untrusted X.509 certificate. The application code must consult the `req.client.authorized`, `req.client.authorizationError`, and `req.client.getPeerCertificate()` values before deciding to accept or reject a request. 

If the client certificate is trusted, `req.client.authorized` is *true*. Otherwise `req.client.authorizationError` contains one of the following error codes, or a hexadecimal number for more esoteric error conditions:

* CERT_E_EXPIRED  
* CERT_E_UNTRUSTEDCA  
* TRUST_E_CERT_SIGNATURE  
* CRYPT_E_REVOKED  
* CERT_E_UNTRUSTEDROOT  
* CERT_E_WRONG_USAGE  
* CRYPT_E_NO_REVOCATION_CHECK  
* CRYPT_E_REVOCATION_OFFLINE  
* CERT_E_CHAINING 

Whenever the client presented an X.509 certificate (even one that failed validation), the `req.client.getPeerCertificate()` will return an object describing some key properties of the certificate, e.g.:

```text
{   
	subject: 'CN=localhost',
	issuer: 'CN=localhost',
	valid_from: 'Mon, 12 Aug 2013 14:23:23 GMT',
	valid_to: 'Wed, 31 Dec 2098 22:00:00 GMT',
	fingerprint: 'C0:8E:29:A6:96:CC:C5:A2:5E:2F:3B:9A:94:34:EA:62:4B:83:7E:E8'
}
```

The httpsys module can optionally pass the entire, encoded X.509 certificate presented by the client to the application. To enable this feature, set the `HTTPSYS_EXPORT_CLIENT_CERT=1` environment variable. As a result the object returned from `req.client.getPeerCertificate()` will also contain an `encoded` property with a Buffer that holds the raw X.509 certificate. This may be useful for customized certificate validation, for example using the .NET's [X509Chain](http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509chain.aspx) class accessed via [Edge.js](http://tjanczuk.github.io/edge). 

### HTTP.SYS output caching

The HTTP.SYS output caching feature enables you to [dramatically improve](http://tomasz.janczuk.org/2012/08/the-httpsys-stack-for-nodejs-apps-on.html) the throughput of your Node.js HTTP[S] server if you are repeatedly serving responses that can be cached for even a short period (e.g. 1 second). The first time an HTTP request is made, HTTP.SYS caches the response generated by the Node.js application in an efficient, in-memory, kernel mode cache. For all similar requests that arrive within the specified cache duration, HTTP.SYS then serves the response directly from the cache without invoking the Node.js application. 

By default HTTP.SYS output caching is disabled. To enable output caching for your application, set the `HTTPSYS_CACHE_DURATION` environment variable to the desired default cache duration in seconds, e.g. 

```
set HTTPSYS_CACHE_DURATION=1
node server.js
```

There are no changes required in the code of your application, unless you want to override the default cache duration for a particular HTTP response: 

```javascript
require('httpsys').slipstream(); 

var http = require('http');

http.createServer(function (req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.cacheDuration = 60; // cache this particular response for 60 seconds
  res.end('Hello, world!');
}).listen(8080);
```

Note that if you do not set the `HTTPSYS_CACHE_DURATION` environment variable at all, the `cacheDuration` property in code remains ineffective. If you want to enable output caching only for carefully chosen set of responses, set `HTTPSYS_CACHE_DURATION` to 0 (zero), and then use `cacheDuration` in code to change this default for selected responses. 

You can inspect the state of the HTTP.SYS output cache using the `netsh http show cachestate` command. 

### WebSockets

The httpsys module supports WebSockets on Windows 8 or Windows Server 2012 or later. The module was proved to work with the [einaros/ws](https://github.com/einaros/ws) module for WebSockets, as well as the [socket.io](http://socket.io/) module for WebSockets and HTTP long polling. Check out tests for code samples. 

### Cluster

Cluster functionality is supported. 

Note that when you use HTTP.SYS output caching, using cluster is typically not necessary to fully saturate server CPU. This is because HTTP.SYS is multi-threaded, and with adequate request load can fully utilize the server CPU serving responses from the cache.

### Other configuration options

There are a few other aspects of the `httpsys` module behavior that are controlled with environment variables:

* `HTTPSYS_CACHE_DURATION` - default lifetime of the HTTP response in the the HTTP.SYS output cache in seconds. If unset, the HTTP.SYS output caching feature is completely disabled. 
* `HTTPSYS_BUFFER_SIZE` - the size of the memory buffer used for reading HTTP requests in bytes. The default is 4096. If you are expecting HTTP requests with headers that exceed this size (e.g. large cookies or authentication), you may need to increase this value to e.g. 16384.
* `HTTPSYS_REQUEST_QUEUE_LENGTH` - the maximum number of HTTP requests that HTTP.SYS will allow to be queued up before responding with a 503 to new requests. This is helpful in addressing short-lived spikes in traffic. The default is 5000.
* `HTTPSYS_PENDING_READ_COUNT` - the number of async read requests for new HTTP requests that `httpsys` will maintain at any given point in time. The default is 1. 
* `HTTPSYS_NATIVE` - fully qualified file name of the native httpsys.node module to use; this is useful when working with custom builds of the `httpsys` module.  
* `HTTPSYS_EXPORT_CLIENT_CERT` - if set to 1, raw client X.509 certificates negotiated during SSL handshake will be provided to the application as a `encoded` property of the object returned from `req.client.getPeerCertificate()`.  

### APIs

The httpsys module exposes the following functions:

* *slipstream()*. Calling this function first in your application replaces Node.js'es built-in server side HTTP(S) stack with httpsys. This means that subsequent calls to `require('http')` or `require('https')` will return a version of the module based on HTTP.SYS.  
* *http()*. If you don't want to globally replace the built-in HTTP(S) modules with httpsys by calling `slipstream()`, you can obtain an isolated reference to the httpsys version of the built-in *http* module with a call to `http()`. 
* *https()*. Similar to `http()`, only for HTTPS. 

### Building

To build httpsys, you must have Visual Studio 2012 or Visual Studio Express 2012 for Windows Desktop. There are a few ways to build depending on what you want to achieve. 

To build httpsys for all supported versions and flavors of Node.js: (0.6.20, 0.8.22, 0.10.15) x (x32, x64), call

```text
tools\buildall.bat
```

The first time you call the command above, respective versions of Node.js and node-gyp will be dynamically downloaded from the web. Subsequent builds will use the downloaded versions and be faster. The build results in several flavors of *httpsys.node* module binplaced in directories under *lib\native\win32* and ready to use. 

To build a debug version of httpsys for the version and flavor of Node.js currently installed on your machine, call:

```text
tools\builddev.bat
```

Once you set the `HTTPSYS_NATIVE` environment variable to point to the resulting *httpsys.node* binary, you can run your apps with that custom version of httpsys. Useful for debugging and development. 

### Running tests

To run tests using the version and falvor of Node.js installed on your machine, call

```text
npm test
```

To run tests against all the versions and flavors against which httpsys was built, call:

```text
test\testall.bat
```

Note that prior to calling *testall.bat* you must have successfuly built the module using `tools\buildall.bat` to ensure the required versions of *node.exe* are present in expected locations. 

### Feedback

Please provide feedback and ask questions [here](https://github.com/tjanczuk/httpsys/issues/new). Collaboration welcome - I do take contributions. 
