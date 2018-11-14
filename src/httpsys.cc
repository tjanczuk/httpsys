#include "httpsys.h"
#include <nan.h>

using namespace v8;

#pragma comment(lib, "ws2_32.lib")

 /*
 Design notes:
 - Only one async operation per regular HTTP request should be outstanding at a time. JavaScript
 must ensure not to initiate another async operation (e.g. httpsys_write_body) before
 the ongoing one completes. This implies JavaScript must manage a state machine around a request
 and buffer certain calls from user code (e.g. writing multiple chunks of response body before
 previous write completes)
 - Only up to two async operations per upgraded HTTP request should be outstanding at the time: one for reading
 of the requst, and one for writing of the response. The native module supports separate event pumps for
 the request and response of upgraded request.
 - Native resources are released by native code if async operation completes with error.
 - If JavaScript encounters an error it must explicitly request native resources to be released.
 In particular there is no exception contract between JavaScript callback and native code.
 - JavaScript cannot make any additional calls into native in the context of a particular request
 after it has been called with an error event type; at that time all native resources had already
 been cleaned up.
 - The Socket underlying the HTTP request and response implements the allowHalfOpen=true semantics using
 HTTP.SYS APIs, which is the Node.js behavior. This allows responses to be sent after the request has finished
 and requests to be received after the response has finished. Native resources are only freed when both ends
 of the connection are closed.
 */

BOOL							debugOut;
char							logBuf[1024];
int								initialBufferSize;
ULONG							requestQueueLength;
int								pendingReadCount;

Nan::Callback					*callback;
Nan::Persistent<Function>		bufferConstructor;

HTTP_CACHE_POLICY				cachePolicy;
ULONG							defaultCacheDuration;
Nan::Persistent<ObjectTemplate>	httpsysObject;
RtlTimeToSecondsSince1970Func	RtlTimeToSecondsSince1970Impl;
BOOL							httpsys_export_client_cert;

// Global V8 strings reused across requests
Nan::Persistent<String>			v8uv_httpsys_server;
Nan::Persistent<String>			v8method;
Nan::Persistent<String>			v8req;
Nan::Persistent<String>			v8httpHeaders;
Nan::Persistent<String>			v8httpVersionMajor;
Nan::Persistent<String>			v8httpVersionMinor;
Nan::Persistent<String>			v8eventType;
Nan::Persistent<String>			v8code;
Nan::Persistent<String>			v8url;
Nan::Persistent<String>			v8uv_httpsys;
Nan::Persistent<String>			v8data;
Nan::Persistent<String>			v8statusCode;
Nan::Persistent<String>			v8reason;
Nan::Persistent<String>			v8knownHeaders;
Nan::Persistent<String>			v8unknownHeaders;
Nan::Persistent<String>			v8isLastChunk;
Nan::Persistent<String>			v8chunks;
Nan::Persistent<String>			v8id;
Nan::Persistent<String>			v8value;
Nan::Persistent<String>			v8cacheDuration;
Nan::Persistent<String>			v8disconnect;
Nan::Persistent<String>			v8noDelay;
Nan::Persistent<String>			v8clientCertInfo;
Nan::Persistent<String>			v8cert;
Nan::Persistent<String>			v8authorizationError;
Nan::Persistent<String>			v8subject;
Nan::Persistent<String>			v8issuer;
Nan::Persistent<String>			v8validFrom;
Nan::Persistent<String>			v8validTo;
Nan::Persistent<String>			v8fingerprint;
Nan::Persistent<String>			v8encoded;
Nan::Persistent<String>			v8remoteAddress;

// Maps HTTP_HEADER_ID enum to v8 string
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa364526(v=vs.85).aspx

Nan::Persistent<String> v8httpRequestHeaderNames[HttpHeaderRequestMaximum];

char* requestHeaders[] = {
	"cache-control",
	"connection",
	"date",
	"keep-alive",
	"pragma",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
	"warning",
	"alive",
	"content-length",
	"content-type",
	"content-encoding",
	"content-language",
	"content-location",
	"content-md5",
	"content-range",
	"expires",
	"last-modified",
	"accept",
	"accept-charset",
	"accept-encoding",
	"accept-language",
	"authorization",
	"cookie",
	"expect",
	"from",
	"host",
	"if-match",
	"if-modified-since",
	"if-none-match",
	"if-range",
	"if-unmodified-since",
	"max-forwards",
	"proxy-authorization",
	"referer",
	"range",
	"te",
	"translate",
	"user-agent"
};

// Maps HTTP_VERB enum to V8 string
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa364664(v=vs.85).aspx

Nan::Persistent<String> v8verbs[HttpVerbMaximum];

char* verbs[] = {
	NULL,
	NULL,
	NULL,
	"OPTIONS",
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"TRACE",
	"CONNECT",
	"TRACK",
	"MOVE",
	"COPY",
	"PROPFIND",
	"PROPPATCH",
	"MKCOL",
	"LOCK",
	"UNLOCK",
	"SEARCH"
};

// Processing common to most exported methods:
// - declare handle scope and hr
// - extract uv_httpsys_t from the internal field of the object passed as the first parameter
//uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)Handle<Object>::Cast(args[0])->GetPointerFromInternalField(0);

#define HTTPSYS_EXPORT_PREAMBLE \
    HRESULT hr; \
	Handle<Object> o = Handle<Object>::Cast(info[0]); \
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)Nan::GetInternalFieldPointer(o, 0);

HRESULT httpsys_uv_httpsys_init(uv_httpsys_t* uv_httpsys, uv_async_cb callback)
{
	HRESULT hr;

	ErrorIf(NULL != uv_httpsys->uv_async, E_FAIL);
	ErrorIf(NULL == (uv_httpsys->uv_async = new uv_async_t), ERROR_NOT_ENOUGH_MEMORY);
	RtlZeroMemory(uv_httpsys->uv_async, sizeof(uv_async_t));
	CheckError(uv_async_init(uv_default_loop(), uv_httpsys->uv_async, callback));
	uv_httpsys->uv_async->data = uv_httpsys;
	uv_httpsys->uv_httpsys_server->refCount++;
	Log("uv_async_init '%p', uv_httpsys_server->refCount '%d'\n", uv_httpsys->uv_async, uv_httpsys->uv_httpsys_server->refCount);
	return S_OK;

Error:
	Log("uv_async_init FAILED as uv_httpsys->uv_async not null\n");
	return hr;
}

void httpsys_close_uv_async_cb(uv_handle_t* uv_handle)
{
	Log("httpsys_close_uv_async_cb called '%p'\n", uv_handle);
	delete uv_handle;
}

HRESULT httpsys_uv_httpsys_close(uv_httpsys_t* uv_httpsys)
{
	HRESULT hr;

	Log("entered httpsys_uv_httpsys_close for request id '%I64u, uv_async '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys->uv_async);
	ErrorIf(NULL == uv_httpsys->uv_async, E_FAIL);
	Log("calling uv_close");
	uv_close((uv_handle_t*)uv_httpsys->uv_async, httpsys_close_uv_async_cb);
	uv_httpsys->uv_async = NULL;
	uv_httpsys->uv_httpsys_server->refCount--;
	Log("uv_async cleared and uv_httpsys_server->refCount '%d'\n", uv_httpsys->uv_httpsys_server->refCount);

	return S_OK;

Error:
	Log("httpsys_uv_httpsys_close failed as uv_async already null\n");
	return hr;
}

Handle<Value> httpsys_make_callback(Handle<Value> options)
{
	Nan::EscapableHandleScope handleScope;
	Handle<Value> argv[] = { options };

	Nan::TryCatch try_catch;

	Handle<Value> result;
	Nan::Call(*callback, 1, argv).ToLocal(&result);

	if (try_catch.HasCaught()) {
		Nan::FatalException(try_catch);
	}
	return handleScope.Escape(result);
}

Handle<Object> httpsys_create_event(uv_httpsys_server_t* uv_httpsys_server, int eventType)
{
	Handle<Object> o = Nan::New(uv_httpsys_server->event);
	o->Set(Nan::New(v8eventType), Nan::New<v8::Number>(eventType));
	return Nan::New(uv_httpsys_server->event);
}

Handle<Object> httpsys_create_event(uv_httpsys_t* uv_httpsys, int eventType)
{
	Handle<Object> o = Nan::New(uv_httpsys->event);
	o->Set(Nan::New(v8eventType), Nan::New<v8::Number>(eventType));
	return Nan::New(uv_httpsys->event);
}

Handle<Value> httpsys_notify_error(uv_httpsys_server_t* uv_httpsys_server, uv_httpsys_event_type errorType, unsigned int code)
{
	Nan::EscapableHandleScope handleScope;
	Log("_NOTIFY_ERROR: httpsys_server event type '%d', code '%d'\n", errorType, code);
	Handle<Object> error = httpsys_create_event(uv_httpsys_server, errorType);
	error->Set(Nan::New(v8code), Nan::New<v8::Number>(code));
	return handleScope.Escape(httpsys_make_callback(error));
}

Handle<Value> httpsys_notify_error(uv_httpsys_t* uv_httpsys, uv_httpsys_event_type errorType, unsigned int code)
{
	Nan::EscapableHandleScope handleScope;
	Log("_NOTIFY_ERROR: httpsys event type '%d', code '%d'\n", errorType, code);
	Handle<Object> error = httpsys_create_event(uv_httpsys, errorType);
	error->Set(Nan::New(v8code), Nan::New<v8::Number>(code));
	return handleScope.Escape(httpsys_make_callback(error));
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void httpsys_new_request_callback(uv_async_t* handle)
{
	Nan::HandleScope handleScope;
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)handle->data;
	NTSTATUS overlappedResult = (NTSTATUS)uv_httpsys->uv_async->async_req.u.io.overlapped.Internal;
	ULONG overlappedLength = (ULONG)uv_httpsys->uv_async->async_req.u.io.overlapped.InternalHigh;
	PHTTP_REQUEST request = (PHTTP_REQUEST)uv_httpsys->buffer;

	Log("REQ: httpsys_new_request_callback, request id '%I64u', result 0x%08x, buffer size '%d', required '%d'\n",
		request->RequestId,
		overlappedResult,
		uv_httpsys->bufferSize,
		overlappedLength);

	httpsys_uv_httpsys_close(uv_httpsys);

	//if the async callback fails check for server shutting down. Actual value returned
	//overlappedResult for shut down is STATUS_CANCELLED (0xc0000120).
	if (S_OK != overlappedResult)
	{
		//are we shutting down?
		if (uv_httpsys->uv_httpsys_server->closing = TRUE)
		{
			Log("server is closing down, abort processing new request\n");
			//free resources
			Log("freeing uv_httpsys request id = '%I64u'\n", uv_httpsys->requestId);
			httpsys_free(uv_httpsys, TRUE);
			uv_httpsys = NULL;
			return;
		}
	}

	//if the http request header is bigger then the available buffer, 
	//the async receive request will fail
	if (S_OK == overlappedResult && request->pRawUrl != NULL) {
		Log("REQ: received raw url '%s'\n",
			request->pRawUrl);
	}

	BOOL isUpgrade = FALSE;

	// Copy the request ID assigned to the request by HTTP.SYS to uv_httpsys 
	// to start subsequent async operations related to this request

	uv_httpsys->requestId = request->RequestId;

	// Increase the count of new read requests to initialize to replace the one that just completed.
	// Actual initialization will be done in the uv_prepare callback httpsys_prepare_new_requests 
	// associated with this server.

	uv_httpsys->uv_httpsys_server->readsToInitialize++;
	Log("REQ: incrementing readsToInitialize to ready next request, new value '%d'\n", 
		uv_httpsys->uv_httpsys_server->readsToInitialize);

	// Initialize the JavaScript representation of an event object that will be used
	// to marshall data into JavaScript for the lifetime of this request.
	Local<ObjectTemplate> tpl = Nan::New<ObjectTemplate>(httpsysObject);
	Local<Object> o = tpl->NewInstance();
	uv_httpsys->event.Reset(o);

	Nan::SetInternalFieldPointer(o, 0, (void*)uv_httpsys);
	o->Set(Nan::New(v8uv_httpsys_server), Nan::New(uv_httpsys->uv_httpsys_server->event));

	// Process async completion
	if (S_OK != overlappedResult)
	{
		// Async completion failed - notify JavaScript
		Log("REQ: creating new request error\n");

		//JPW ADDED
		uv_httpsys->refCount++;

		httpsys_notify_error(
			uv_httpsys,
			HTTPSYS_ERROR_NEW_REQUEST,
			(unsigned int)overlappedResult);

		uv_httpsys->refCount--;
		if (uv_httpsys->refCount == 0) {
			Log("REQ: freeing uv_httpsys request id = '%I64u'\n", uv_httpsys->requestId);
			httpsys_free(uv_httpsys, TRUE);
			uv_httpsys = NULL;
		}
	}
	else
	{
		Log("REQ: building new request, request id = '%I64u'\n", uv_httpsys->requestId);
		// New request received, build event to pass to JavaScript
		Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_NEW_REQUEST);

		// Create the 'req' object representing the request
		Handle<Object> req = Nan::New<Object>();
		event->Set(Nan::New(v8req), req);

		char remoteAddress[INET6_ADDRSTRLEN];
		memset(remoteAddress, 0, INET6_ADDRSTRLEN);
		if (request->Address.pRemoteAddress != NULL) {
			//extract remote connection ip
			inet_ntop(
				request->Address.pRemoteAddress->sa_family,
				get_in_addr((struct sockaddr *)request->Address.pRemoteAddress),
				remoteAddress,
				sizeof remoteAddress);
		}
		req->Set(Nan::New(v8remoteAddress), Nan::New(remoteAddress).ToLocalChecked());

		// Add HTTP verb information
		if (HttpVerbUnknown == request->Verb)
		{
			req->Set(Nan::New(v8method), Nan::New(request->pUnknownVerb).ToLocalChecked());
		}
		else
		{
			req->Set(Nan::New(v8method), Nan::New(v8verbs[request->Verb]));
		}

		// Add known HTTP header information
		Handle<Object> headers = Nan::New<Object>();
		req->Set(Nan::New(v8httpHeaders), headers);

		for (int i = 0; i < HttpHeaderRequestMaximum; i++)
		{
			if (request->Headers.KnownHeaders[i].RawValueLength > 0)
			{
				if (7 == i) {
					// This is an upgrade header indicating a potential upgrade
					Log("REQ: received an upgrade request");
					isUpgrade = TRUE;
				}

				headers->Set(Nan::New(v8httpRequestHeaderNames[i]), Nan::New(
					request->Headers.KnownHeaders[i].pRawValue,
					request->Headers.KnownHeaders[i].RawValueLength).ToLocalChecked());
			}
		}

		// Add custom HTTP header information
		for (int i = 0; i < request->Headers.UnknownHeaderCount; i++)
		{
			// Node expects header names in lowercase.
			// In-place convert unknown header names to lowercase. 

			for (int k = 0; k < request->Headers.pUnknownHeaders[i].NameLength; k++) {
				((PSTR)request->Headers.pUnknownHeaders[i].pName)[k] =
					tolower(request->Headers.pUnknownHeaders[i].pName[k]);
			}

			headers->Set(
				Nan::New(
					request->Headers.pUnknownHeaders[i].pName,
					request->Headers.pUnknownHeaders[i].NameLength).ToLocalChecked(),
				Nan::New(
					request->Headers.pUnknownHeaders[i].pRawValue,
					request->Headers.pUnknownHeaders[i].RawValueLength).ToLocalChecked());
		}

		// TODO: process trailers

		// Add HTTP version information

		req->Set(Nan::New(v8httpVersionMajor), Nan::New<Number>(request->Version.MajorVersion));
		req->Set(Nan::New(v8httpVersionMinor), Nan::New<Number>(request->Version.MinorVersion));

		// Add URL information

		req->Set(Nan::New(v8url), Nan::New(request->pRawUrl, request->RawUrlLength).ToLocalChecked());

		// Add client X.509 information

		if (NULL != request->pSslInfo && NULL != request->pSslInfo->pClientCertInfo)
		{
			req->Set(
				Nan::New(v8clientCertInfo),
				httpsys_create_client_cert_info(request->pSslInfo->pClientCertInfo));
		}

		// Invoke the JavaScript callback passing event as the only paramater
		Log("REQ: passing event to javascript request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
		Handle<Value> result = httpsys_make_callback(event);
		Log("REQ: back from javascript uv_httpsys = '%p'\n", (void*)uv_httpsys);

		if (result->IsBoolean() && result->BooleanValue())
		{
			Log("REQ: true returned from javascript, continue... checking for request body\n");
			// If the callback response is 'true', proceed to process the request body. 
			// Otherwise request had been paused and will be resumed asynchronously from JavaScript
			// with a call to httpsys_resume.

			if (0 == (request->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) && !isUpgrade)
			{
				Log("REQ: body-less request, create END request and pass to javascript, request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
				// This is a body-less request. Notify JavaScript the request is finished.
				// Note that for HTTP upgrade paths this flag appears not to be set.

				Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_END_REQUEST);
				httpsys_make_callback(event);
				Log("REQ: back from javascript uv_httpsys = '%p'\n", (void*)uv_httpsys);
			}
			else
			{
				// Start synchronous body reading loop.
				Log("REQ: **Start synchronous body reading loop, isUpgrade = '%d'\n", isUpgrade);
				httpsys_read_request_body_loop(uv_httpsys);
			}
		}
	}
	Log("REQ: exiting httpsys_new_request_callback\n");
}

Handle<Object> httpsys_create_client_cert_info(PHTTP_SSL_CLIENT_CERT_INFO info)
{
	char* slowBuffer;
	Nan::EscapableHandleScope scope;
	Handle<Object> certInfo = Nan::New<Object>();
	// Set the authentication result
	certInfo->Set(Nan::New(v8authorizationError), Nan::New<Number>(info->CertFlags));
	// Decode the certificate and create V8 representation
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa381955(v=vs.85).aspx

	PCCERT_CONTEXT certContext = CertCreateCertificateContext(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		info->pCertEncoded,
		info->CertEncodedSize);

	DWORD size;
	char* str = NULL;
	ULONG time;

	if (NULL != certContext)
	{
		Handle<Object> cert = Nan::New<Object>();
		certInfo->Set(Nan::New(v8cert), cert);
		// Set the Subject's X500 name
		size = CertNameToStr(
			X509_ASN_ENCODING,
			&certContext->pCertInfo->Subject,
			CERT_X500_NAME_STR,
			NULL,
			0);

		if (size > 0 && (NULL != (str = (char*)malloc(size))))
		{
			CertNameToStr(
				X509_ASN_ENCODING,
				&certContext->pCertInfo->Subject,
				CERT_X500_NAME_STR,
				str,
				size);

			cert->Set(Nan::New(v8subject), Nan::New(str).ToLocalChecked());
			free(str);
			str = NULL;
		}

		// Set the Issuer's X500 name

		size = CertNameToStr(
			X509_ASN_ENCODING,
			&certContext->pCertInfo->Issuer,
			CERT_X500_NAME_STR,
			NULL,
			0);

		if (size > 0 && (NULL != (str = (char*)malloc(size))))
		{
			CertNameToStr(
				X509_ASN_ENCODING,
				&certContext->pCertInfo->Issuer,
				CERT_X500_NAME_STR,
				str,
				size);

			cert->Set(Nan::New(v8issuer), Nan::New(str).ToLocalChecked());
			free(str);
			str = NULL;
		}

		// Set the validity period

		if (RtlTimeToSecondsSince1970Impl)
		{
			RtlTimeToSecondsSince1970Impl(
				(PLARGE_INTEGER)&certContext->pCertInfo->NotBefore,
				&time);

			cert->Set(Nan::New(v8validFrom), Nan::New<Number>(time));

			RtlTimeToSecondsSince1970Impl(
				(PLARGE_INTEGER)&certContext->pCertInfo->NotAfter,
				&time);

			cert->Set(Nan::New(v8validTo), Nan::New<Number>(time));
		}

		// Set the thumbprint 

		size = 0;
		if (CertGetCertificateContextProperty(certContext, CERT_SHA1_HASH_PROP_ID, NULL, &size)
			&& (NULL != (str = (char*)malloc(size)))
			&& CertGetCertificateContextProperty(certContext, CERT_SHA1_HASH_PROP_ID, str, &size))
		{
			if (NULL != (slowBuffer = (char*)malloc(size)))
			{
				memcpy(slowBuffer, (char*)str, size);
				Handle<Value> args[] = { Nan::NewBuffer(slowBuffer,size).ToLocalChecked(), Nan::New<Number>(size), Nan::New<Number>(0) };
				Local<Function> cons = Nan::New<v8::Function>(bufferConstructor);
				Handle<Object> fastBuffer;
				cons->NewInstance(Nan::GetCurrentContext(), 3, args).ToLocal(&fastBuffer);
				cert->Set(Nan::New(v8fingerprint), fastBuffer);
				free(str);
				str = NULL;
			}
			else 
			{
				Log("CertGetCertificateContextProperty: failed to allocate memory\n");
			}
		}

		// If HTTPSYS_EXPORT_CLIENT_CERT environment variable is set,
		// export the raw X.509 certificate presented by the client
		if (httpsys_export_client_cert)
		{
			if (NULL != (slowBuffer = (char*)malloc(certContext->cbCertEncoded)))
			{
				memcpy(slowBuffer, (char*)certContext->pbCertEncoded, certContext->cbCertEncoded);
				Handle<Value> args[] = { Nan::NewBuffer(slowBuffer, certContext->cbCertEncoded).ToLocalChecked(), Nan::New<Number>(certContext->cbCertEncoded), Nan::New<Number>(0) };
				Local<Function> cons = Nan::New<v8::Function>(bufferConstructor);
				Handle<Object> fastBuffer;
				cons->NewInstance(Nan::GetCurrentContext(), 3, args).ToLocal(&fastBuffer);
				cert->Set(Nan::New(v8encoded), fastBuffer);
			}
			else
			{
				Log("httpsys_export_client_cert: failed to allocate memory\n");
			}
		}
		CertFreeCertificateContext(certContext);
	}

	return scope.Escape(certInfo);
}

HRESULT httpsys_initiate_new_request(uv_httpsys_t* uv_httpsys)
{
	HRESULT hr;

	// Create libuv async handle and initialize it
	Log("REQ: entered httpsys_initiate_new_request request id = '%I64u'\n", uv_httpsys->requestId);

	CheckError(httpsys_uv_httpsys_init(uv_httpsys, (uv_async_cb)httpsys_new_request_callback));

	// Allocate initial buffer to receice the HTTP request

	uv_httpsys->bufferSize = initialBufferSize;
	ErrorIf(NULL == (uv_httpsys->buffer = malloc(uv_httpsys->bufferSize)), ERROR_NOT_ENOUGH_MEMORY);
	RtlZeroMemory(uv_httpsys->buffer, uv_httpsys->bufferSize);

	// Initiate async receive of a new request with HTTP.SYS, using the OVERLAPPED
	// associated with the default libuv event loop. 

	hr = HttpReceiveHttpRequest(
		uv_httpsys->uv_httpsys_server->requestQueue,
		HTTP_NULL_ID,
		0,
		(PHTTP_REQUEST)uv_httpsys->buffer,
		uv_httpsys->bufferSize,
		NULL,
		&uv_httpsys->uv_async->async_req.u.io.overlapped);

	Log("REQ: result from HttpReceiveHttpRequest '%d'\n", hr);

	if (NO_ERROR == hr)
	{
		// Synchronous completion.  
		Log("REQ: synchronous completion, calling httpsys_new_request_callback\n");
		httpsys_new_request_callback(uv_httpsys->uv_async);
	}
	else
	{
		ErrorIf(ERROR_IO_PENDING != hr, hr);
	}
	Log("REQ: exited httpsys_initiate_new_request\n");
	return S_OK;

Error:
	Log("REQ: httpsys_initiate_new_request has errored hr = '%d'\n", hr);
	return hr;
}

void httpsys_free_chunks(uv_httpsys_t* uv_httpsys)
{
	Log("entered httpsys_free_chunks for request id '%I64u\n", uv_httpsys->requestId);
	if (uv_httpsys->chunk.FromMemory.pBuffer)
	{
		free(uv_httpsys->chunk.FromMemory.pBuffer);
		RtlZeroMemory(&uv_httpsys->chunk, sizeof(uv_httpsys->chunk));
	}
}

void httpsys_free(uv_httpsys_t* uv_httpsys, BOOL error)
{
	if (NULL != uv_httpsys)
	{
		Log("httpsys_free called request id ='%I64u', uv_httpsys = '%p', uv_httpsys_peer = '%p', refcount = '%d'\n", uv_httpsys->requestId, (void*)uv_httpsys, uv_httpsys->uv_httpsys_peer, uv_httpsys->refCount);

		// For upgraded requests, two uv_httpsys instances exist: one for request and the other for response.
		// The last one to close cleans up shared resources as well as disposes of the peer. 
		uv_httpsys->closed = TRUE;

		Log("freeing chunks...\n");
		httpsys_free_chunks(uv_httpsys);

		if (!uv_httpsys->event.IsEmpty()) {
			Log("freeing uv_httpsys->event...\n");
			uv_httpsys->event.Reset();
		}

		if (uv_httpsys->response.pReason) {
			Log("freeing uv_httpsys->response.pReason...\n");
			free((void*)uv_httpsys->response.pReason);
		}

		for (int i = 0; i < HttpHeaderResponseMaximum; i++) {
			if (uv_httpsys->response.Headers.KnownHeaders[i].pRawValue) {
				Log("freeing known header '%.*s'\n", 
					uv_httpsys->response.Headers.KnownHeaders[i].RawValueLength,
					uv_httpsys->response.Headers.KnownHeaders[i].pRawValue);

				free((void*)uv_httpsys->response.Headers.KnownHeaders[i].pRawValue);
			}
		}

		if (uv_httpsys->response.Headers.pUnknownHeaders) {
			for (int i = 0; i < uv_httpsys->response.Headers.UnknownHeaderCount; i++) {
				if (uv_httpsys->response.Headers.pUnknownHeaders[i].pName) {
					Log("freeing unknown header name '%.*s'\n", 
						uv_httpsys->response.Headers.pUnknownHeaders[i].NameLength,
						uv_httpsys->response.Headers.pUnknownHeaders[i].pName);

					free((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pName);
				}
				if (uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue) {
					Log("freeing unknown header value '%.*s'\n", 
						uv_httpsys->response.Headers.pUnknownHeaders[i].RawValueLength,
						uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue);

					free((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue);
				}
			}
			Log("freeing header memory '%p'\n", (void*)uv_httpsys->response.Headers.pUnknownHeaders);
			free(uv_httpsys->response.Headers.pUnknownHeaders);
		}

		RtlZeroMemory(&uv_httpsys->response, sizeof(uv_httpsys->response));

		if (uv_httpsys->uv_async) {
			Log("requesting close of uv_async '%p\n", (void*)uv_httpsys->uv_async);
			httpsys_uv_httpsys_close(uv_httpsys);
		}

		if (NULL != uv_httpsys->buffer) {
			Log("freeing uv_httpsys->buffer '%p'\n", (void*)uv_httpsys->buffer);
			free(uv_httpsys->buffer);
			uv_httpsys->buffer = NULL;
		}

		if (NULL != uv_httpsys->uv_httpsys_peer) {
			Log("this is an upgraded connection, freeing...\n")
			// The uv_httpsys structure is paired with another in the HTTP upgrade scenario to 
			// support concurrent reads and writes. Disposal logic:
			// 1. During normal operation (no error) the second uv_httpsys to be freed disposes the pair. 
			// 2. If an error occurrs:
			// 2.1. If there is an async operation pending against the second uv_httpsys, it is marked
			//      for disposal. The async completion callback will re-enter httpsys_free for the second
			//      uv_httpsys structure in order to finish the cleanup.
			// 2.2. If there is no async operation pending against the second uv_httpsys, the pair
			//      is disposed immediately.

			if (uv_httpsys->uv_httpsys_peer->closed) {
				// #1
				Log("scenario #1, (no error) the second uv_httpsys to be freed disposes the pair\n");
				delete uv_httpsys->uv_httpsys_peer;
				uv_httpsys->uv_httpsys_peer = NULL;
				delete uv_httpsys;
				uv_httpsys = NULL;
			}
			else if (error) {
				if (uv_httpsys->uv_httpsys_peer->uv_async) {
					// #2.1
					Log("scenario #2.1, If there is an async operation pending against the second uv_httpsys, it is marked for disposal. The async completion callback will re-enter httpsys_free for the second uv_httpsys structure in order to finish the cleanup\n");
					uv_httpsys->uv_httpsys_peer->disconnect = TRUE;
				}
				else {
					// #2.2
					Log("scenario #2.2, If there is no async operation pending against the second uv_httpsys, the pair is disposed immediately\n");
					httpsys_free(uv_httpsys->uv_httpsys_peer, FALSE);
				}
			}
		}
		else {

			// The regular HTTP request scenario - single uv_httpsys instance. 
			Log("regular http request scenario, delete uv_httpsys instance\n");
			delete uv_httpsys;
			uv_httpsys = NULL;
		}
	}
	else {
		Log("httpsys_free ignored as uv_httpsys is already NULL, uv_httpsys = '%p'\n", (void*)uv_httpsys);
	}
}

void httpsys_read_request_body_callback(uv_async_t* handle)
{
	//HTTPSYS_CALLBACK_PREAMBLE
	Nan::HandleScope handleScope;
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)handle->data;
	Log("REQ: entered httpsys_read_request_body_callback, synchronous '%d', request id '%I64u'\n", uv_httpsys->synchronous, uv_httpsys->requestId);

	NTSTATUS overlappedResult = (NTSTATUS)uv_httpsys->uv_async->async_req.u.io.overlapped.Internal;
	ULONG overlappedLength = (ULONG)uv_httpsys->uv_async->async_req.u.io.overlapped.InternalHigh;
	httpsys_uv_httpsys_close(uv_httpsys);
	PHTTP_REQUEST request = (PHTTP_REQUEST)uv_httpsys->buffer;
	int lastError = 0;
	char* slowBuffer;

	// Process async completion
	if (uv_httpsys->disconnect)
	{
		Log("REQ: disconnection received during operation, free request resources\n");
		// A request was made to disconnect the client when an async operation was in progress. 
		// Now that the async operation completed, disregard the results and free up resources.  

		httpsys_free(uv_httpsys, FALSE);
		uv_httpsys = NULL;
	}
	else if (ERROR_HANDLE_EOF == overlappedResult || 0 == overlappedLength)
	{
		Log("REQ: end of body\n");
		// End of request body - notify JavaScript
		BOOL freePending = NULL != uv_httpsys->uv_httpsys_peer;

		if (!uv_httpsys->responseStarted) {
			// Do not emit the `end` event if the app already started writing the response
			Log("REQ: sending END event to javascript request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
			Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_END_REQUEST);
			Handle<Value> result = httpsys_make_callback(event);
			//assume the worst, if an error code is not returned
			lastError = ERROR_CONNECTION_INVALID;
			//extract any errors
			if (result->IsNumber()) {
				lastError = result->Int32Value();
				Log("REQ: result from httpsys_end_request error = '%d'\n", lastError);
			}
			else {
				Log("REQ: result from httpsys_end_request invalid number returned\n");
			}

			Log("REQ: back from javascript uv_httpsys = '%p'\n", (void*)uv_httpsys);
			//during this callback a failed response write can occur 
			//resulting in native resources being freed
		}

		//if the last error was an invalid connection, all native resources
		//would have already been cleaned up so do not do it again
		if (freePending && lastError != ERROR_CONNECTION_INVALID && lastError != ERROR_INVALID_HANDLE) {
			// This is an upgraded request which has a peer uv_httpsys to handle the response.
			// Since the request uv_httpsys is no longer needed, deallocate it. 
			Log("REQ: free pending, this is an upgraded request which has a peer uv_httpsys to handle the response\n");
			httpsys_free(uv_httpsys, FALSE);
			uv_httpsys = NULL;
		}
	}
	else if (S_OK != overlappedResult)
	{
		// Async completion failed - notify JavaScript
		Log("REQ: async completion failed\n");

		if (!uv_httpsys->responseStarted) {
			// Do not emit the `error` event if the app already started writing the response
			Log("REQ: read body request async completion failed\n");
			httpsys_notify_error(
				uv_httpsys,
				HTTPSYS_ERROR_READ_REQUEST_BODY,
				(unsigned int)overlappedResult);
		}

		Log("REQ: free uv_httpsys\n");
		httpsys_free(uv_httpsys, TRUE);
		uv_httpsys = NULL;
	}
	else
	{
		Log("REQ: send body chunk to javascript\n");
		// Successful completion - send body chunk to JavaScript as a Buffer

		BOOL continueReading = TRUE;

		// Good explanation of native Buffers at 
		// http://sambro.is-super-awesome.com/2011/03/03/creating-a-proper-buffer-in-a-node-c-addon/

		if (!uv_httpsys->responseStarted) {
			// Do not emit the `data` event if the app already started writing the response
			Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_REQUEST_BODY);
			ULONG length = overlappedLength;
			Log("REQ: response not started, build body buffer\n");

			//slow buffer is a pointer to an HTTP request structure
			if (NULL != (slowBuffer = (char*)malloc(length)))
			{
				memcpy(slowBuffer, (char*)uv_httpsys->buffer, length);
				Handle<Value> args[] = { Nan::CopyBuffer(slowBuffer, length).ToLocalChecked(), Nan::New<Number>(length), Nan::New<Number>(0) };

				Local<Function> cons = Nan::New<v8::Function>(bufferConstructor);
				Handle<Object> fastBuffer;
				cons->NewInstance(Nan::GetCurrentContext(), 3, args).ToLocal(&fastBuffer);
				event->Set(Nan::New(v8data), fastBuffer);
				Log("REQ: calling javascript: httpsys_request_body request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
				Handle<Value> result = httpsys_make_callback(event);
				Log("REQ: back from javascript uv_httpsys = '%p'\n", (void*)uv_httpsys);

				free(slowBuffer);

				continueReading = result->IsBoolean() && result->BooleanValue();
			} 
			else {
				continueReading = FALSE;
				Log("REQ: failed to allocate memory will creating slow buffer\n");
			}
		}

		if (continueReading)
		{
			Log("REQ: continuing reading body\n");
			// If the callback response is 'true', proceed to read more of the request body. 
			// Otherwise request had been paused and will be resumed asynchronously from JavaScript
			// with a call to httpsys_resume.
			if (!uv_httpsys->synchronous)
			{
				Log("REQ: synchronous body reading, calling httpsys_read_request_body_loop\n");
				httpsys_read_request_body_loop(uv_httpsys);
			}
		}
	}
	Log("REQ: exiting httpsys_read_request_body_callback\n");
}

HRESULT httpsys_read_request_body_loop(uv_httpsys_t* uv_httpsys)
{
	HRESULT hr = S_OK;

	Log("REQ: entered httpsys_read_request_body_loop\n");
	
	// Continue reading the request body synchronously until EOF, and error, 
	// request is paused or async completion is expected.
	while (NULL != uv_httpsys && NO_ERROR == (hr = httpsys_initiate_read_request_body(uv_httpsys)))
	{
		Log("REQ: synchronous read body completion\n");
		// Use the "status" parameter to the callback as a mechanism to return data
		// from the callback. If upon return the uv_httpsys is still not NULL,
		// it means there was no error and the request was not paused by the application.
        uv_httpsys->synchronous = 1; /*JPW Added*/
		httpsys_read_request_body_callback(uv_httpsys->uv_async);
	}

	Log("REQ: exited httpsys_read_request_body_loop\n");
	return (NO_ERROR == hr || ERROR_HANDLE_EOF == hr || ERROR_IO_PENDING == hr) ? S_OK : hr;
}

HRESULT httpsys_initiate_read_request_body(uv_httpsys_t* uv_httpsys)
{
	Nan::HandleScope handleScope;
	HRESULT hr;

	Log("REQ: entered httpsys_initiate_read_request_body, request id = '%I64u'\n", uv_httpsys->requestId);
	// Initialize libuv handle representing this async operation
    uv_httpsys->synchronous = 0; /*JPW Added*/
	CheckError(httpsys_uv_httpsys_init(uv_httpsys, (uv_async_cb)httpsys_read_request_body_callback));

	// Initiate async receive of the HTTP request body

	hr = HttpReceiveRequestEntityBody(
		uv_httpsys->uv_httpsys_server->requestQueue,
		uv_httpsys->requestId,
		0,
		uv_httpsys->buffer,
		uv_httpsys->bufferSize,
		NULL,
		&uv_httpsys->uv_async->async_req.u.io.overlapped);

	Log("REQ: HttpReceiveRequestEntityBody request id '%I64u', result '%d'\n", uv_httpsys->requestId, hr);

	if (ERROR_HANDLE_EOF == hr)
	{
		// End of request body, decrement libuv loop ref count since no async completion will follow
		// and generate JavaScript event
		Log("REQ: end of body received\n");

		httpsys_uv_httpsys_close(uv_httpsys);
		if (!uv_httpsys->responseStarted) {
			// Do not emit the `end` event if the app already started writing the response
			Log("REQ: sending END to javascript request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
			Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_END_REQUEST);
			httpsys_make_callback(event);
			Log("REQ: back from javascript, uv_httpsys = '%p'\n", (void*)uv_httpsys);
		}
		else {
			Log("REQ: response already started, not sending END to javascript\n");
		}
	}
	else if (ERROR_IO_PENDING != hr && NO_ERROR != hr)
	{
		Log("REQ: reading request body has failed...\n");
		// Initiation failed - notify JavaScript
		if (!uv_httpsys->responseStarted) {
			// Do not emit the `error` event if the app already started writing the response
			httpsys_notify_error(uv_httpsys, HTTPSYS_ERROR_INITIALIZING_READ_REQUEST_BODY, hr);
		}

		httpsys_free(uv_httpsys, TRUE);
		uv_httpsys = NULL;
	}

	// Result of NO_ERROR at this point means synchronous completion that must be handled by the caller
	// since the IO completion port of libuv will not receive a completion.

Error:
	Log("REQ: exiting httpsys_initiate_read_request_body, hr = '%d'\n", hr);
	return hr;
}

void httpsys_init(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	v8::Handle<v8::Object> options = info[0]->ToObject();

	callback = new Nan::Callback(options->Get(Nan::New("callback").ToLocalChecked()).As<Function>());
	initialBufferSize = options->Get(Nan::New("initialBufferSize").ToLocalChecked())->Int32Value();
	requestQueueLength = options->Get(Nan::New("requestQueueLength").ToLocalChecked())->Int32Value();
	pendingReadCount = options->Get(Nan::New("pendingReadCount").ToLocalChecked())->Int32Value();
	int cacheDuration = options->Get(Nan::New("cacheDuration").ToLocalChecked())->Int32Value();

	if (0 > cacheDuration)
	{
		cachePolicy.Policy = HttpCachePolicyNocache;
		cachePolicy.SecondsToLive = 0;
	}
	else
	{
		cachePolicy.Policy = HttpCachePolicyTimeToLive;
		defaultCacheDuration = cacheDuration;
	}

	debugOut = getenv("HTTP_SYS_DEBUG") ? TRUE : FALSE;
	info.GetReturnValue().SetUndefined();
}


void httpsys_prepare_new_requests(uv_prepare_t* handle)
{
	Nan::HandleScope handleScope;
	uv_httpsys_server_t* uv_httpsys_server = CONTAINING_RECORD(handle, uv_httpsys_server_t, uv_prepare);
	HRESULT hr;
	uv_httpsys_t* uv_httpsys = NULL;

	if (uv_httpsys_server->closing && 0 == uv_httpsys_server->refCount)
	{
		Log("REQ: httpsys_prepare_new_requests server closing with refcount === 0\n");
		// The HTTP.SYS server is closing as a result of a call to Server.close(). 
		// The HTTP.SYS request queue has already been closed in httpsys_stop_listen. 
		// Given that the refCount of pending async operatoins has reached zero, we can
		// now perform final cleanup of the server, including notifying JavaScript that 
		// closing has completed. 

		// Stop this callback from executing again.
		Log("uv_prepare_stop\n");
		uv_prepare_stop(&uv_httpsys_server->uv_prepare);

		Log("informing javascript of server closing\n");
		httpsys_make_callback(httpsys_create_event(uv_httpsys_server, HTTPSYS_SERVER_CLOSED));

		Log("releasing server resources\n");
		// Clean up data structures
		uv_httpsys_server->event.Reset();

		//delete uv_httpsys_server;
		uv_httpsys_server = NULL;

		Log("terminating http server\n");
		// Terminate HTTP Server. The corresponding HttpInitiate call was made in 
		// httpsys_listen.
		CheckError(HttpTerminate(
			HTTP_INITIALIZE_SERVER,
			NULL));

		return;
	}

	while (uv_httpsys_server->readsToInitialize)
	{
		Log("\nREQ: preparing new request: current reads to initialise '%d'\n", uv_httpsys_server->readsToInitialize);
		// TODO: address a situation when some new requests fail while others not - cancel them?
		ErrorIf(NULL == (uv_httpsys = new uv_httpsys_t), ERROR_NOT_ENOUGH_MEMORY);
		RtlZeroMemory(uv_httpsys, sizeof(uv_httpsys_t));
		uv_httpsys->uv_httpsys_server = uv_httpsys_server;
		CheckError(httpsys_initiate_new_request(uv_httpsys));
		uv_httpsys = NULL;
		uv_httpsys_server->readsToInitialize--;
		Log("REQ: finished current request initialisation, decrementing readsToInitialize count, new value '%d'\n", uv_httpsys_server->readsToInitialize);
	}

	return;

Error:

	Log("REQ: httpsys_prepare_new_requests has errored, freeing uv_httpsys\n");
	if (NULL != uv_httpsys)
	{
		httpsys_free(uv_httpsys, TRUE);
		uv_httpsys = NULL;
	}
	httpsys_notify_error(uv_httpsys_server, HTTPSYS_ERROR_INITIALIZING_REQUEST, hr);
	return;
}

void httpsys_listen(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	Isolate* isolate = Isolate::GetCurrent();
	EscapableHandleScope handleScope(isolate);
	HRESULT hr;
	HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_2;
	WCHAR url[MAX_PATH + 1];
	WCHAR requestQueueName[MAX_PATH + 1];
	HTTP_BINDING_INFO bindingInfo;
	uv_loop_t* loop;
	uv_httpsys_t* uv_httpsys = NULL;
	uv_httpsys_server_t* uv_httpsys_server = NULL;
	BOOL success = 0;
	HANDLE handle = NULL;
	Local<ObjectTemplate> tpl = Nan::New<ObjectTemplate>(httpsysObject);
	Local<Object> o = tpl->NewInstance();

	Log("start listen called\n");
	// Process arguments

	Local<Array> urls = Local<Array>::Cast(info[0]);

	// Lazy initialization of HTTP.SYS

	CheckError(HttpInitialize(
		HttpApiVersion,
		HTTP_INITIALIZE_SERVER,
		NULL));

	// Create uv_httpsys_server_t

	ErrorIf(NULL == (uv_httpsys_server = new uv_httpsys_server_t), ERROR_NOT_ENOUGH_MEMORY);
	RtlZeroMemory(uv_httpsys_server, sizeof(uv_httpsys_server_t));

	// use the first url path as the request queue name by replacing slahes in the URL with _
	// to make it a valid file name.
	urls->Get(0)->ToString()->Write((uint16_t*)requestQueueName, 0, MAX_PATH);

	for (WCHAR* current = requestQueueName; *current; current++)
	{
		if (L'/' == *current)
		{
			*current = L'_';
		}
	}

	// Create HTTP.SYS request queue (one per URL). Request queues are named 
	// to allow sharing between processes and support cluster. 
	// First try to obtain a handle to a pre-existing queue with the name
	// based on the listen URL. If that fails, create a new named request queue. 
	Log("checking if request queue exists '%ws'\n", requestQueueName);

	hr = HttpCreateRequestQueue(
		HttpApiVersion,
		requestQueueName,
		NULL,
		HTTP_CREATE_REQUEST_QUEUE_FLAG_OPEN_EXISTING,
		&uv_httpsys_server->requestQueue);

	Log("result from HttpCreateRequestQueue = %d\n", hr);

	if (ERROR_FILE_NOT_FOUND == hr)
	{
		// Request queue by that name does not exist yet, try to create it

		Log("attempting to create request queue\n");

		CheckError(HttpCreateRequestQueue(
			HttpApiVersion,
			requestQueueName,
			NULL,
			0,
			&uv_httpsys_server->requestQueue));

		Log("created request queue\n");

		// Create HTTP.SYS session and associate it with URL group containing the
		// single listen URL. 

		CheckError(HttpCreateServerSession(
			HttpApiVersion,
			&uv_httpsys_server->sessionId,
			NULL));

		Log("done HttpCreateServerSession\n");

		CheckError(HttpCreateUrlGroup(
			uv_httpsys_server->sessionId,
			&uv_httpsys_server->groupId,
			NULL));

		Log("done HttpCreateUrlGroup\n");

		//repeat for all specified url's
		for (unsigned int i = 0; i < urls->Length(); i++) {
			urls->Get(i)->ToString()->Write((uint16_t*)url, 0, MAX_PATH);

			Log("adding url to group '%ws'\n", url);

			HRESULT hres = HttpAddUrlToUrlGroup(
				uv_httpsys_server->groupId,
				url,
				0,
				NULL);

			Log("result = '%d'\n", hres);

			CheckError(hres);
		}
		// Set the request queue length
		CheckError(HttpSetRequestQueueProperty(
			uv_httpsys_server->requestQueue,
			HttpServerQueueLengthProperty,
			&requestQueueLength,
			sizeof(requestQueueLength),
			0,
			NULL));

		Log("done HttpSetRequestQueueProperty\n");

		// Bind the request queue with the URL group to enable receiving
		// HTTP traffic on the request queue. 
		RtlZeroMemory(&bindingInfo, sizeof(HTTP_BINDING_INFO));
		bindingInfo.RequestQueueHandle = uv_httpsys_server->requestQueue;
		bindingInfo.Flags.Present = 1;

		CheckError(HttpSetUrlGroupProperty(
			uv_httpsys_server->groupId,
			HttpServerBindingProperty,
			&bindingInfo,
			sizeof(HTTP_BINDING_INFO)));

		Log("done HttpSetUrlGroupProperty\n");
	}
	else
	{
		CheckError(hr);
	}
	// Associate the HTTP.SYS request queue handle with the IO completion port 
	// of the default libuv event loop used by node. This will cause 
	// async completions related to the HTTP.SYS request queue to execute 
	// on the node.js thread. The event loop will process these events as
	// UV_ASYNC handle types, beacuse a call to uv_async_init will be made
	// every time an async operation is started with HTTP.SYS. On Windows, 
	// uv_async_init associates the OVERLAPPED structure representing the 
	// async operation with the uv_async_t handle that embeds it, which allows
	// the event loop to map the OVERLAPPED instance back to the async 
	// callback to invoke when the IO completion port is signaled. 

	loop = uv_default_loop();
	handle = CreateIoCompletionPort(
		uv_httpsys_server->requestQueue,
		loop->iocp,
		(ULONG_PTR)uv_httpsys_server->requestQueue,
		0);

	ErrorIf(handle == NULL, GetLastError());

	Log("done CreateIoCompletionPort\n");

	// Configure the request queue to prevent queuing a completion to the libuv
	// IO completion port when an async operation completes synchronously. 

	success = SetFileCompletionNotificationModes(
		uv_httpsys_server->requestQueue,
		FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE);

	ErrorIf(!success, GetLastError());

	Log("done SetFileCompletionNotificationModes\n");

	// Initiate uv_prepare associated with this server that will be responsible for 
	// initializing new pending receives of new HTTP reqests against HTTP.SYS 
	// to replace completed ones. This logic will run once per iteration of the libuv event loop.
	// The first execution of the callback will initiate the first batch of reads. 

	uv_prepare_init(loop, &uv_httpsys_server->uv_prepare);
	uv_prepare_start(&uv_httpsys_server->uv_prepare, (uv_prepare_cb)httpsys_prepare_new_requests);

	Log("REQ: initialising readsToInitialize to '%d'\n", pendingReadCount);
	uv_httpsys_server->readsToInitialize = pendingReadCount;

	// The result wraps the native pointer to the uv_httpsys_server_t structure.
	// It also doubles as an event parameter to JavaScript callbacks scoped to the entire server.
	uv_httpsys_server->event.Reset(o);
	Nan::SetInternalFieldPointer(o, 0, (void*)uv_httpsys_server);
	o->Set(Nan::New(v8uv_httpsys_server), Nan::New(uv_httpsys_server->event));
	info.GetReturnValue().Set(Nan::New(uv_httpsys_server->event));
	return;

Error:

	if (NULL != uv_httpsys_server) {
		if (HTTP_NULL_ID != uv_httpsys_server->groupId)	{
			HttpCloseUrlGroup(uv_httpsys_server->groupId);
		}
		if (NULL != uv_httpsys_server->requestQueue) {
			HttpCloseRequestQueue(uv_httpsys_server->requestQueue);
		}
		if (HTTP_NULL_ID != uv_httpsys_server->sessionId) {
			HttpCloseServerSession(uv_httpsys_server->sessionId);
		}
		delete uv_httpsys_server;
		uv_httpsys_server = NULL;
	}

	if (NULL != uv_httpsys) {
		httpsys_free(uv_httpsys, TRUE);
		uv_httpsys = NULL;
	}
	info.GetReturnValue().Set(isolate->ThrowException(Nan::New<Number>(hr)));
}


void httpsys_stop_listen(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	HRESULT hr;
	Handle<Object> o = Handle<Object>::Cast(info[0]);
	uv_httpsys_server_t* uv_httpsys_server = (uv_httpsys_server_t*)Nan::GetInternalFieldPointer(o, 0);
	Log("stop listen called\n");

	// Mark the HTTP.SYS listener as closing. Next time the httpsys_prepare_new_requests
	// callback is entered, and the pending async operations associated with the server have 
	// drained (as indicated by the uv_httpsys_server->refCount), it will have a chance to 
	// perform final cleanup.
	uv_httpsys_server->closing = TRUE;

	// Close the HTTP.SYS URL group
	if (HTTP_NULL_ID != uv_httpsys_server->groupId)	{
		Log("closing url group\n");
		CheckError(HttpCloseUrlGroup(uv_httpsys_server->groupId));
	}
	// Perform graceful shutdown of the HTTP.SYS request queue, then close the queue.
	// This will cause all pending async operations to be cancelled, which the system
	// will be notified about via the IO completion port of the main libuv event loop. 
	// Appropriate async callbacks will be executed to react to these cancellations.

	if (NULL != uv_httpsys_server->requestQueue)
	{
		Log("shutting down request queue\n");
		CheckError(HttpShutdownRequestQueue(uv_httpsys_server->requestQueue));
		Log("closing request queue\n");
		CheckError(HttpCloseRequestQueue(uv_httpsys_server->requestQueue));
	}

	// Close the HTTP.SYS server session
	if (HTTP_NULL_ID != uv_httpsys_server->sessionId) {
		Log("closing server session %llu\n", uv_httpsys_server->sessionId);
		CheckError(HttpCloseServerSession(uv_httpsys_server->sessionId));
	}
	Log("returning from stop listen\n");
	info.GetReturnValue().SetUndefined();
	return;

Error:
	Log("RESP: error during httpsys_stop_listen hr = '%ld'\n", hr);
	Isolate* isolate = Isolate::GetCurrent();
	info.GetReturnValue().Set(isolate->ThrowException(Nan::New<Number>(hr)));
}

void httpsys_resume(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	HTTPSYS_EXPORT_PREAMBLE;
	Log("REQ: httpsys_resume called from javascript request id = '%I64u'\n", uv_httpsys->requestId);
	CheckError(httpsys_read_request_body_loop(uv_httpsys));
	info.GetReturnValue().SetUndefined();
	return;

Error:
	Log("RESP: error during httpsys_resume hr = '%d'\n", hr);
	// uv_httpsys had been freed already
	Isolate* isolate = Isolate::GetCurrent();
	EscapableHandleScope handleScope(isolate);
	info.GetReturnValue().Set(isolate->ThrowException(Nan::New<Number>(hr)));
}

void httpsys_write_headers(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	HRESULT hr;
	Handle<Object> o = Handle<Object>::Cast(info[0]);
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)Nan::GetInternalFieldPointer(o, 0);

	Handle<Object> options = info[0]->ToObject();
	String::Utf8Value reason(options->Get(Nan::New(v8reason)));
	Handle<Object> unknownHeaders;
	Handle<Array> headerNames;
	v8::Handle<v8::String> headerName;
	Handle<Array> knownHeaders;
	Handle<Object> knownHeader;
	Handle<Value> cacheDuration;
	ULONG flags = 0;
	unsigned int statusCode;
	uv_httpsys_t* uv_httpsys_req = NULL;

	// Enable NAGLE if requested
	if (!options->Get(Nan::New(v8noDelay))->BooleanValue()) {
		flags |= HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING;
	}

	// Get response status code
	statusCode = options->Get(Nan::New(v8statusCode))->Uint32Value();
	Log("\nRESP: httpsys_write_headers called from javascript, status '%d', request id '%I64u'\n", statusCode, uv_httpsys->requestId);

	// If this is an accepted upgrade response, create another uv_httpsys intance 
	// to allow processing request and response concurrently. Use the new uv_httpsys instance 
	// for writing of the response, inluding sending back the HTTP response headers. The old 
	// uv_httpsys instance will continue to be used for reading of the request.

	if (101 == statusCode) {
		// Instruct HTTP.SYS to treat subsequent reads and writes of the HTTP request and response as
		// opaque. This allows higher level protocols like WebSockets to implement custom framing.
		Log("RESP: socket upgraded requested\n");
		flags |= HTTP_SEND_RESPONSE_FLAG_OPAQUE;

		// Create an initialize uv_httpsys for writing of the response
		ErrorIf(NULL == (uv_httpsys->uv_httpsys_peer = new uv_httpsys_t), ERROR_NOT_ENOUGH_MEMORY);
		RtlZeroMemory(uv_httpsys->uv_httpsys_peer, sizeof(uv_httpsys_t));
		uv_httpsys->uv_httpsys_peer->uv_httpsys_server = uv_httpsys->uv_httpsys_server;
		uv_httpsys->uv_httpsys_peer->requestId = uv_httpsys->requestId;
		
		uv_httpsys->uv_httpsys_peer->event.Reset(uv_httpsys->event);
		uv_httpsys->uv_httpsys_peer->uv_httpsys_peer = uv_httpsys;
		// Switch to using the newly created uv_httpsys for the rest of this function
		uv_httpsys_req = uv_httpsys;
		uv_httpsys = uv_httpsys->uv_httpsys_peer;

		Log("RESP: ***upgrade response: swap uv_httpsys_peer = '%p', with uv_httpsys = '%p'\n", (void*)uv_httpsys, (void*)uv_httpsys_req);
	}
	else {
		// For regular HTTP requests, once the response had been initiated, further
		// `data` and `end` events will not be emitted even if the request had
		// not been read entirely. This flag is used to stop issuing read requests
		// against HTTP.SYS for this request. 
		uv_httpsys->responseStarted = TRUE;
	}
	uv_httpsys->response.StatusCode = statusCode;

	// Initialize libuv handle representing this async operation
	uv_httpsys->synchronousWrite = FALSE; /*JPW ADDED*/
	CheckError(httpsys_uv_httpsys_init(uv_httpsys, (uv_async_cb)httpsys_write_callback));

	// If the request is to be disconnected, it indicates a rejected HTTP upgrade request. 
	// In that case the request is closed and native resources deallocated. 
	if (options->Get(Nan::New(v8disconnect))->BooleanValue()) {
		Log("RESP: disconnect set from javascript, it indicates a rejected HTTP upgrade request\n");
		uv_httpsys->disconnect = TRUE;
	}

	if (uv_httpsys->disconnect) {
		Log("RESP: disconnect flag set, responding with DISCONNECT response\n");

		uv_httpsys->disconnectProcessed = TRUE;
		flags |= HTTP_SEND_RESPONSE_FLAG_DISCONNECT;
		hr = HttpSendHttpResponse(
			uv_httpsys->uv_httpsys_server->requestQueue,
			uv_httpsys->requestId,
			flags,
			&uv_httpsys->response,
			NULL,
			NULL,
			NULL,
			0,
			&uv_httpsys->uv_async->async_req.u.io.overlapped,
			NULL);

		Log("RESP: HttpSendHttpResponse result '%d'\n", hr);

		if (NO_ERROR == hr)
		{
			//Synchronous completion. 
			uv_httpsys->synchronousWrite = TRUE; /*JPW Added*/
			httpsys_write_callback(uv_httpsys->uv_async);

			//uv_httpsys may have been freed inside this routine if the write completed
			Log("RESP: back from httpsys_write_callback uv_httpsys = '%p'\n", (void*)uv_httpsys);
		}
		else
		{
			ErrorIf(ERROR_IO_PENDING != hr, hr);
		}
		info.GetReturnValue().Set(ERROR_IO_PENDING == hr ? true : false);
		return;
	}

	//make sure uv_httpsys is still valid
	if (uv_httpsys != NULL) {
		// Set reason 
		ErrorIf(NULL == (uv_httpsys->response.pReason = (PCSTR)malloc(reason.length())),
			ERROR_NOT_ENOUGH_MEMORY);
		uv_httpsys->response.ReasonLength = reason.length();
		memcpy((void*)uv_httpsys->response.pReason, *reason, reason.length());

		// Set known headers

		knownHeaders = Handle<Array>::Cast(options->Get(Nan::New(v8knownHeaders)));
		for (unsigned int i = 0; i < knownHeaders->Length(); i++)
		{
			knownHeader = Handle<Object>::Cast(knownHeaders->Get(i));
			int headerIndex = knownHeader->Get(Nan::New(v8id))->Int32Value();
			String::Utf8Value header(knownHeader->Get(Nan::New(v8value)));
			ErrorIf(NULL == (uv_httpsys->response.Headers.KnownHeaders[headerIndex].pRawValue =
				(PCSTR)malloc(header.length())),
				ERROR_NOT_ENOUGH_MEMORY);
			uv_httpsys->response.Headers.KnownHeaders[headerIndex].RawValueLength = header.length();
			memcpy((void*)uv_httpsys->response.Headers.KnownHeaders[headerIndex].pRawValue,
				*header, header.length());
		}

		// Set unknown headers

		unknownHeaders = Handle<Object>::Cast(options->Get(Nan::New(v8unknownHeaders)));
		headerNames = unknownHeaders->GetOwnPropertyNames();
		if (headerNames->Length() > 0)
		{
			ErrorIf(NULL == (uv_httpsys->response.Headers.pUnknownHeaders =
				(PHTTP_UNKNOWN_HEADER)malloc(headerNames->Length() * sizeof(HTTP_UNKNOWN_HEADER))),
				ERROR_NOT_ENOUGH_MEMORY);
			RtlZeroMemory(uv_httpsys->response.Headers.pUnknownHeaders,
				headerNames->Length() * sizeof(HTTP_UNKNOWN_HEADER));
			uv_httpsys->response.Headers.UnknownHeaderCount = headerNames->Length();
			for (int i = 0; i < uv_httpsys->response.Headers.UnknownHeaderCount; i++)
			{
				headerName = headerNames->Get(i)->ToString();
				String::Utf8Value headerNameUtf8(headerName);
				String::Utf8Value headerValueUtf8(unknownHeaders->Get(headerName));
				uv_httpsys->response.Headers.pUnknownHeaders[i].NameLength = headerNameUtf8.length();
				ErrorIf(NULL == (uv_httpsys->response.Headers.pUnknownHeaders[i].pName =
					(PCSTR)malloc(headerNameUtf8.length())),
					ERROR_NOT_ENOUGH_MEMORY);
				memcpy((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pName,
					*headerNameUtf8, headerNameUtf8.length());
				uv_httpsys->response.Headers.pUnknownHeaders[i].RawValueLength = headerValueUtf8.length();
				ErrorIf(NULL == (uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue =
					(PCSTR)malloc(headerValueUtf8.length())),
					ERROR_NOT_ENOUGH_MEMORY);
				memcpy((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue,
					*headerValueUtf8, headerValueUtf8.length());
			}
		}

		// Prepare response body and determine flags

		CheckError(httpsys_initialize_body_chunks(options, uv_httpsys, &flags));
		if (uv_httpsys->chunk.FromMemory.pBuffer)
		{
			uv_httpsys->response.EntityChunkCount = 1;
			uv_httpsys->response.pEntityChunks = &uv_httpsys->chunk;
		}

		// Determine cache policy

		if (HttpCachePolicyTimeToLive == cachePolicy.Policy)
		{
			// If HTTP.SYS output caching is enabled, establish the duration to cache for
			// based on the setting on the message or the global default, in that order of precedence

			cacheDuration = options->Get(Nan::New(v8cacheDuration));
			cachePolicy.SecondsToLive = cacheDuration->IsUint32() ? cacheDuration->Uint32Value() : defaultCacheDuration;
		}
		// TOOD: support response trailers

		// Initiate async send of the HTTP response headers and optional body
		hr = HttpSendHttpResponse(
			uv_httpsys->uv_httpsys_server->requestQueue,
			uv_httpsys->requestId,
			flags,
			&uv_httpsys->response,
			&cachePolicy,
			NULL,
			NULL,
			0,
			&uv_httpsys->uv_async->async_req.u.io.overlapped,
			NULL);

		Log("RESP: sending response data: HttpSendHttpResponse result '%d'\n", hr);

		if (NO_ERROR == hr)
		{
			// Synchronous completion. 
			//httpsys_write_callback(uv_httpsys->uv_async, 1);
			uv_httpsys->synchronousWrite = TRUE;
			httpsys_write_callback(uv_httpsys->uv_async);
			Log("RESP: back from httpsys_write_callback uv_httpsys = '%p'\n", (void*)uv_httpsys);
		}
		else
		{
			ErrorIf(ERROR_IO_PENDING != hr, hr);
		}
	}
	info.GetReturnValue().Set(ERROR_IO_PENDING == hr ? true : false);
	return;

Error:
	Log("RESP: error during httpsys_write_headers\n");
	if (uv_httpsys_req != NULL) {
		Log("we have a uv_httpsys_req so we have an upgraded connection, clearing original req uv_httpsys_req = '%I64u'\n", uv_httpsys_req->requestId);
	}
	httpsys_free(uv_httpsys_req, TRUE);
	uv_httpsys_req = NULL;

	Log("call httpsys_free for 'uv_httpsys' request '%I64u'\n", uv_httpsys->requestId);
	httpsys_free(uv_httpsys, TRUE);
	uv_httpsys = NULL;

	Isolate* isolate = Isolate::GetCurrent();
	info.GetReturnValue().Set(isolate->ThrowException(Nan::New<Number>((int)hr)));
}

void httpsys_write_callback(uv_async_t* handle)
{
	Nan::HandleScope handleScope;
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)handle->data;
	NTSTATUS overlappedResult = (NTSTATUS)uv_httpsys->uv_async->async_req.u.io.overlapped.Internal;
	ULONG overlappedLength = (ULONG)uv_httpsys->uv_async->async_req.u.io.overlapped.InternalHigh;
	
	Log("RESP: httpsys_write_callback called for request '%I64u'\n", uv_httpsys->requestId);
	BOOL calledSynchronously = uv_httpsys->synchronousWrite;
	// Process async completion
	if (calledSynchronously) {
		Log("**SYNCHRONOUS**\n");
	}
	else {
		Log("**ASYNCHRONOUSLY**\n");
	}
	httpsys_uv_httpsys_close(uv_httpsys);
	PHTTP_REQUEST request = (PHTTP_REQUEST)uv_httpsys->buffer;
	HRESULT hr = S_OK;

	if (uv_httpsys->disconnectProcessed) {
		Log("RESP: client termination due to upgrade or an error, freeing resources\n");
		// This was a best-effort termination of a client connection after an unaccepted 
		// HTTP upgrade request or an error. Free up native resources regardless of the outcome 
		// of the async operation. 

		httpsys_free(uv_httpsys, FALSE);
		uv_httpsys = NULL;
	}
	else if (uv_httpsys->disconnect) {
		Log("RESP: client disconnect request when async in progress\n");
		// A request was made to disconnect the client when an async operation was in progress. 
		// Now that the async operation completed, initiate the disconnection again. 

		uv_httpsys->disconnectProcessed = TRUE;

		uv_httpsys->synchronousWrite = FALSE;
		CheckError(httpsys_uv_httpsys_init(uv_httpsys, (uv_async_cb)httpsys_write_callback));

		hr = HttpSendResponseEntityBody(
			uv_httpsys->uv_httpsys_server->requestQueue,
			uv_httpsys->requestId,
			HTTP_SEND_RESPONSE_FLAG_DISCONNECT,
			0,
			NULL,
			NULL,
			NULL,
			0,
			&uv_httpsys->uv_async->async_req.u.io.overlapped,
			NULL);

		Log("RESP: HttpSendResponseEntityBody returned hr = '%ld', request '%I64u'\n", hr, uv_httpsys->requestId);

		if (ERROR_IO_PENDING != hr)
		{
			// Synchronous completion or an error - execute callback manually to release the uv_httpsys.
			uv_httpsys->synchronousWrite = TRUE;
			httpsys_write_callback(uv_httpsys->uv_async);
			Log("RESP: back from httpsys_write_callback uv_httpsys = '%p'\n", (void*)uv_httpsys);
		}
	}
	else if (S_OK != overlappedResult)
	{
		Log("RESP: write async completion failed\n");
		// Async completion failed - notify JavaScript
		uv_httpsys->refCount++;

		httpsys_notify_error(
			uv_httpsys,
			HTTPSYS_ERROR_WRITING,
			(unsigned int)overlappedResult);

		uv_httpsys->refCount--;
		Log("RESP: ref count = '%d'\n", uv_httpsys->refCount);

		if (uv_httpsys->refCount == 0)
		{
			httpsys_free(uv_httpsys, TRUE);
			uv_httpsys = NULL;
		}
	}
	else
	{
		// Successful completion 
		if (!calledSynchronously)
		{
			// Call completed asynchronously - send notification to JavaScript.
			//added ref count as the httpsys_make_callback can result in re-entrance into
			//this function which results in memory being de-allocating more than once
			Log("RESP: informing javascript that response has been written, request id = '%I64u', uv_httpsys = '%p'\n", uv_httpsys->requestId, (void*)uv_httpsys);
			uv_httpsys->refCount++;
			Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_WRITTEN);
			httpsys_make_callback(event);
			Log("RESP: back from javascript uv_httpsys = '%p'\n", (void*)uv_httpsys);
			uv_httpsys->refCount--;
		}

		//this original logic was NOT correct for the following scenario:
		//async write completion calls this routine
		//callback to javascript resulting a further pending response write which is the last chunk
		//returns to this function with last chunk flag set
		//the req resources freed even though there is a pending async write callback
		//causing uv_loop to go bang
		//
		//solution is to check the uv_async handle, if not NULL do not free resources as their is 
		//a pending sync callback
		if (!uv_httpsys->uv_async && uv_httpsys->lastChunkSent && uv_httpsys->refCount == 0)
		{
			Log("RESP: response is complete, free uv_httpsys\n");
			// Response is completed - clean up resources
			httpsys_free(uv_httpsys, FALSE);
			uv_httpsys = NULL;
		}
	}
	Log("RESP: exiting httpsys_write_callback ");
	if (calledSynchronously) {
		Log("**SYNCHRONOUS**\n");
	}
	else {
		Log("**ASYNCHRONOUSLY**\n");
	}
	return;

Error:

	Log("RESP: error during httpsys_write_callback, calling httpsys_free for request '%I64u'\n", uv_httpsys->requestId);
	// The best-effort termination of a client connection failed. Free up the uv_httpsys.

	httpsys_free(uv_httpsys, TRUE);
	uv_httpsys = NULL;
}

HRESULT httpsys_initialize_body_chunks(Handle<Object> options, uv_httpsys_t* uv_httpsys, ULONG* flags)
{
	HRESULT hr;
	Handle<Array> chunks;

	Log("RESP: freeing any previous chunks\n");
	httpsys_free_chunks(uv_httpsys);

	// Copy JavaScript buffers representing response body chunks into a single
	// continuous memory block in an HTTP_DATA_CHUNK. 
	chunks = Handle<Array>::Cast(options->Get(Nan::New(v8chunks)));
	Log("RESP: initialise response body chunks, number of chunks '%d'\n", chunks->Length());

	if (chunks->Length() > 0)
	{
		for (unsigned int i = 0; i < chunks->Length(); i++) {
			Handle<Object> buffer = chunks->Get(i)->ToObject();
			uv_httpsys->chunk.FromMemory.BufferLength += (ULONG)node::Buffer::Length(buffer);
		}

		Log("RESP: total buffer length '%d'\n", uv_httpsys->chunk.FromMemory.BufferLength);

		ErrorIf(NULL == (uv_httpsys->chunk.FromMemory.pBuffer =
			malloc(uv_httpsys->chunk.FromMemory.BufferLength)),
			ERROR_NOT_ENOUGH_MEMORY);

		//initialise buffer write position to start
		char* position = (char*)uv_httpsys->chunk.FromMemory.pBuffer;
		for (unsigned int i = 0; i < chunks->Length(); i++)
		{
			Handle<Object> buffer = chunks->Get(i)->ToObject();
			//copy chunk to buffer
			memcpy(position, node::Buffer::Data(buffer), node::Buffer::Length(buffer));
			//move buffer write position
			position += node::Buffer::Length(buffer);
		}
	}

	// Remove the 'chunks' property from the options object to indicate they have been 
	// consumed.

	ErrorIf(!options->Set(Nan::New(v8chunks), Nan::Undefined()), E_FAIL);

	// Determine whether the last of the response body is to be written out.

	if (options->Get(Nan::New(v8isLastChunk))->BooleanValue())
	{
		Log("RESP: this was the last chunk, setting last chunk sent\n");

		uv_httpsys->lastChunkSent = 1;
		if (uv_httpsys->uv_httpsys_peer) {
			Log("RESP: setting disconnect flag\n");
			// For upgraded requests, the connection must be manually terminated.
			*flags |= HTTP_SEND_RESPONSE_FLAG_DISCONNECT;
		}
	}
	else
	{
		Log("RESP: more data to follow, set more data response flag\n");
		*flags |= HTTP_SEND_RESPONSE_FLAG_MORE_DATA;
	}

	Log("exiting httpsys_initialize_body_chunks\n");
	return S_OK;

Error:

	Log("RESP: error during initialise body chunks, calling httpsys_free_chunks for request '%I64u'\n", uv_httpsys->requestId);
	httpsys_free_chunks(uv_httpsys);

	return hr;
}

void httpsys_write_body(const Nan::FunctionCallbackInfo<v8::Value>& info)
{
	HRESULT hr;
	Handle<Object> o = Handle<Object>::Cast(info[0]);
	uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)Nan::GetInternalFieldPointer(o, 0);

	Handle<Object> options = info[0]->ToObject();
	ULONG flags = 0;

	Log("RESP: httpsys_write_body called from javascript for request id '%I64u'\n", uv_httpsys->requestId);
	// Enable NAGLE if requested

	if (!options->Get(Nan::New(v8noDelay))->BooleanValue()) {
		flags |= HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING;
	}

	// If this is an upgraded HTTP request, use the peer uv_httpsys for the write operation
	if (uv_httpsys->uv_httpsys_peer) {
		uv_httpsys = uv_httpsys->uv_httpsys_peer;
		Log("RESP: this is an upgraded connection, using uv_httpsys(peer) = '%p'\n", (void*)uv_httpsys);
	}

	// Initialize libuv handle representing this async operation
	uv_httpsys->synchronousWrite = FALSE;
	CheckError(httpsys_uv_httpsys_init(uv_httpsys, (uv_async_cb)httpsys_write_callback));

	// Prepare response body and determine flags
	CheckError(httpsys_initialize_body_chunks(options, uv_httpsys, &flags));

	// Initiate async send of the HTTP response body
	hr = HttpSendResponseEntityBody(
		uv_httpsys->uv_httpsys_server->requestQueue,
		uv_httpsys->requestId,
		flags,
		uv_httpsys->chunk.FromMemory.pBuffer ? 1 : 0,
		uv_httpsys->chunk.FromMemory.pBuffer ? &uv_httpsys->chunk : NULL,
		NULL,
		NULL,
		0,
		&uv_httpsys->uv_async->async_req.u.io.overlapped,
		NULL);

	Log("RESP: HttpSendResponseEntityBody: hr = '%d' for request '%I64u'\n", hr, uv_httpsys->requestId);

	if (NO_ERROR == hr)
	{
		// Synchronous completion. 
		uv_httpsys->synchronousWrite = TRUE;
		httpsys_write_callback(uv_httpsys->uv_async);
	}
	else
	{
		ErrorIf(ERROR_IO_PENDING != hr, hr);
	}
	// Return true if async completion is pending and an event will be generated once completed
	info.GetReturnValue().Set(ERROR_IO_PENDING == hr ? true : false);
	return;

Error:

	Log("RESP: error during write body, performing clean-up of request '%I64u'\n", uv_httpsys->requestId);
	httpsys_free(uv_httpsys, TRUE);
	uv_httpsys = NULL;

	Isolate* isolate = Isolate::GetCurrent();
	info.GetReturnValue().Set(isolate->ThrowException(Nan::New<Number>(hr)));
}


void init(v8::Local<v8::Object> target)
{
	// Create V8 representation of HTTP verb strings to reuse across requests
	for (int i = 0; i < HttpVerbMaximum; i++) {
		if (verbs[i]) {
			v8verbs[i].Reset(Nan::New(verbs[i]).ToLocalChecked());
		}
	}

	// Create V8 representation of HTTP header names to reuse across requests
	for (int i = 0; i < HttpHeaderRequestMaximum; i++) {
		if (requestHeaders[i]) {
			v8httpRequestHeaderNames[i].Reset(Nan::New(requestHeaders[i]).ToLocalChecked());
		}
	}

	// Create global V8 strings to reuse across requests
	v8remoteAddress.Reset(Nan::New("remoteAddress").ToLocalChecked());
	v8method.Reset(Nan::New("method").ToLocalChecked());
	v8uv_httpsys_server.Reset(Nan::New("uv_httpsys_server").ToLocalChecked());
	v8req.Reset(Nan::New("req").ToLocalChecked());
	v8httpHeaders.Reset(Nan::New("headers").ToLocalChecked());
	v8httpVersionMinor.Reset(Nan::New("httpVersionMinor").ToLocalChecked());
	v8httpVersionMajor.Reset(Nan::New("httpVersionMajor").ToLocalChecked());
	v8eventType.Reset(Nan::New("eventType").ToLocalChecked());
	v8code.Reset(Nan::New("code").ToLocalChecked());
	v8url.Reset(Nan::New("url").ToLocalChecked());
	v8uv_httpsys.Reset(Nan::New("uv_httpsys").ToLocalChecked());
	v8data.Reset(Nan::New("data").ToLocalChecked());
	v8statusCode.Reset(Nan::New("statusCode").ToLocalChecked());
	v8reason.Reset(Nan::New("reason").ToLocalChecked());
	v8knownHeaders.Reset(Nan::New("knownHeaders").ToLocalChecked());
	v8unknownHeaders.Reset(Nan::New("unknownHeaders").ToLocalChecked());
	v8isLastChunk.Reset(Nan::New("isLastChunk").ToLocalChecked());
	v8chunks.Reset(Nan::New("chunks").ToLocalChecked());
	v8id.Reset(Nan::New("id").ToLocalChecked());
	v8value.Reset(Nan::New("value").ToLocalChecked());
	v8cacheDuration.Reset(Nan::New("cacheDuration").ToLocalChecked());
	v8disconnect.Reset(Nan::New("disconnect").ToLocalChecked());
	v8noDelay.Reset(Nan::New("noDelay").ToLocalChecked());
	v8clientCertInfo.Reset(Nan::New("clientCertInfo").ToLocalChecked());
	v8cert.Reset(Nan::New("cert").ToLocalChecked());
	v8authorizationError.Reset(Nan::New("authorizationError").ToLocalChecked());
	v8subject.Reset(Nan::New("subject").ToLocalChecked());
	v8issuer.Reset(Nan::New("issuer").ToLocalChecked());
	v8validFrom.Reset(Nan::New("valid_from").ToLocalChecked());
	v8validTo.Reset(Nan::New("valid_to").ToLocalChecked());
	v8fingerprint.Reset(Nan::New("fingerprint").ToLocalChecked());
	v8encoded.Reset(Nan::New("encoded").ToLocalChecked());

	// Capture the constructor function of JavaScript Buffer implementation
	bufferConstructor.Reset(Nan::GetCurrentContext()->Global()->Get(Nan::New("Buffer").ToLocalChecked()).As<Function>());

	// Create an object template of an object to roundtrip a native pointer to JavaScript
	Local<ObjectTemplate> o = Nan::New<v8::ObjectTemplate>();
	o->SetInternalFieldCount(1);
	httpsysObject.Reset(o);

	// Obtain reference to RtlTimeToSecondsSince1970 function
	HMODULE ntdll = LoadLibrary("Ntdll.dll");
	RtlTimeToSecondsSince1970Impl =
		(RtlTimeToSecondsSince1970Func)GetProcAddress(ntdll, "RtlTimeToSecondsSince1970");

	// Determine whether to propagate raw client X.509 certificate to the application with HTTPS

	httpsys_export_client_cert = (0 < GetEnvironmentVariable("HTTPSYS_EXPORT_CLIENT_CERT", NULL, 0));

	// Create exports
	target->Set(Nan::New("httpsys_init").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_init)->GetFunction());
	target->Set(Nan::New("httpsys_listen").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_listen)->GetFunction());
	target->Set(Nan::New("httpsys_stop_listen").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_stop_listen)->GetFunction());
	target->Set(Nan::New("httpsys_resume").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_resume)->GetFunction());
	target->Set(Nan::New("httpsys_write_headers").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_write_headers)->GetFunction());
	target->Set(Nan::New("httpsys_write_body").ToLocalChecked(), Nan::New<v8::FunctionTemplate>(httpsys_write_body)->GetFunction());
}

NODE_MODULE(httpsys, init)
