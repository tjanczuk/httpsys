#include "httpsys.h"

/*
Design notes:
- Only one async operation per HTTP request should be outstanding at a time. JavaScript 
  must ensure not to initiate another async operation (e.g. httpsys_write_body) before 
  the ongoing one completes. This implies JavaScript must manage a state machine around a request
  and buffer certain calls from user code (e.g. writing multiple chunks of response body before
  previous write completes)
- Native resources are released by native code if async operation completes with error.
- If JavaScript encounters an error it must explicitly request native resources to be released.
  In particular there is no exception contract between JavaScript callback and native code.
- JavaScript cannot make any additional calls into native in the context of a particular request
  after it has been called with an error event type; at that time all native resources had already 
  been cleaned up.
*/

using namespace v8;

int initialized;
int initialBufferSize;
Persistent<Function> callback;
Persistent<Function> bufferConstructor;

// Global V8 strings reused across requests
Handle<String> v8requestQueue;
Handle<String> v8method;
Handle<String> v8req;
Handle<String> v8httpHeaders;
Handle<String> v8httpVersionMajor;
Handle<String> v8httpVersionMinor;
Handle<String> v8eventType;
Handle<String> v8code;
Handle<String> v8url;
Handle<String> v8uv_httpsys;
Handle<String> v8data;
Handle<String> v8statusCode;
Handle<String> v8reason;
Handle<String> v8knownHeaders;
Handle<String> v8unknownHeaders;
Handle<String> v8isLastChunk;
Handle<String> v8chunks;

// Maps HTTP_HEADER_ID enum to v8 string
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa364526(v=vs.85).aspx
Handle<String> v8httpRequestHeaderNames[HttpHeaderRequestMaximum];
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
Handle<String> v8verbs[HttpVerbMaximum];
char* verbs[] = {
    NULL,
    NULL,
    NULL,
    "OPTIONS",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DETELE",
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

// Processing common to all callbacks from HTTP.SYS:
// - map the uv_async_t handle to uv_httpsys_t
// - decrement event loop reference count to indicate completion of async operation
#define HTTPSYS_CALLBACK_PREAMBLE \
    HandleScope handleScope; \
    uv_httpsys_t* uv_httpsys = CONTAINING_RECORD(handle, uv_httpsys_t, uv_async); \
    uv_unref(uv_httpsys->uv_async.loop); \
    uv_httpsys->uv_async.loop = NULL; \
    PHTTP_REQUEST request = (PHTTP_REQUEST)uv_httpsys->buffer; 

// Processing common to most exported methods:
// - declare handle scope and hr
// - extract uv_httpsys_t from the 'uv_httpsys' member of the object passed as the first parameter
#define HTTPSYS_EXPORT_PREAMBLE \
    HandleScope handleScope; \
    HRESULT hr; \
    uv_httpsys_t* uv_httpsys = (uv_httpsys_t*)args[0]->ToObject()->Get(v8uv_httpsys)->Uint32Value();

Handle<Value> httpsys_make_callback(Handle<Value> options)
{
    HandleScope handleScope;
    Handle<Value> argv[] = { options };

    TryCatch try_catch;

    Handle<Value> result = callback->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught()) {
        node::FatalException(try_catch);
    }

    return handleScope.Close(result);
}

Handle<Object> httpsys_create_event(uv_httpsys_t* uv_httpsys, int eventType)
{
    HandleScope handleScope;
    PHTTP_REQUEST request = (PHTTP_REQUEST)uv_httpsys->buffer; 
    Handle<Object> event = Object::New(); 
    event->Set(v8eventType, Integer::NewFromUnsigned(eventType));
    event->Set(v8uv_httpsys, Integer::NewFromUnsigned((uint32_t)uv_httpsys)); 
    event->Set(v8requestQueue, Integer::NewFromUnsigned((uint32_t)uv_httpsys->requestQueue)); 

    return handleScope.Close(event);
}

Handle<Value> httpsys_notify_error(uv_httpsys_t* uv_httpsys, uv_httpsys_event_type errorType, int code)
{
    HandleScope handleScope;

    Handle<Object> error = httpsys_create_event(uv_httpsys, errorType);
    error->Set(v8code, Integer::NewFromUnsigned(code));

    return handleScope.Close(httpsys_make_callback(error));
}

void httpsys_new_request_callback(uv_async_t* handle, int status)
{
    HTTPSYS_CALLBACK_PREAMBLE
    HRESULT hr;

    // Copy the request ID assigned to the request by HTTP.SYS to uv_httpsys 
    // to start subsequent async operations related to this request

    uv_httpsys->requestId = request->RequestId;

    // Initiate pending read for a new HTTP request to replace the one that just completed

    if (S_OK != (hr = httpsys_initiate_new_request(uv_httpsys->requestQueue)))
    {
        // Initiation failed - notify JavaScript
        httpsys_notify_error(uv_httpsys, HTTPSYS_ERROR_INITIALIZING_REQUEST, hr);
    }

    // Process async completion

    if (S_OK != uv_httpsys->uv_async.async_req.overlapped.Internal)
    {
        // Async completion failed - notify JavaScript
        httpsys_notify_error(
            uv_httpsys, 
            HTTPSYS_ERROR_NEW_REQUEST,
            uv_httpsys->uv_async.async_req.overlapped.Internal);
        httpsys_free(uv_httpsys);
        uv_httpsys = NULL;
    }
    else
    {
        // New request received - notify JavaScript

        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_NEW_REQUEST);

        // Create the 'req' object representing the request

        Handle<Object> req = Object::New();
        event->Set(v8req, req);

        // Add HTTP verb information

        if (HttpVerbUnknown == request->Verb)
        {
            req->Set(v8method, String::New(request->pUnknownVerb));
        }
        else 
        {
            req->Set(v8method, v8verbs[request->Verb]);
        }

        // Add known HTTP header information

        Handle<Object> headers = Object::New();
        req->Set(v8httpHeaders, headers);

        for (int i = 0; i < HttpHeaderRequestMaximum; i++)
        {
            if (request->Headers.KnownHeaders[i].RawValueLength > 0)
            {
                headers->Set(v8httpRequestHeaderNames[i], String::New(
                    request->Headers.KnownHeaders[i].pRawValue,
                    request->Headers.KnownHeaders[i].RawValueLength));
            }
        }

        // Add custom HTTP header information

        for (int i = 0; i < request->Headers.UnknownHeaderCount; i++)
        {
            // TODO: lowercase unknown header names
            headers->Set(
                String::New(
                    request->Headers.pUnknownHeaders[i].pName,
                    request->Headers.pUnknownHeaders[i].NameLength),
                String::New(
                    request->Headers.pUnknownHeaders[i].pRawValue,
                    request->Headers.pUnknownHeaders[i].RawValueLength));
        }

        // TODO: process trailers

        // Add HTTP version information

        req->Set(v8httpVersionMajor, Integer::NewFromUnsigned(request->Version.MajorVersion));
        req->Set(v8httpVersionMinor, Integer::NewFromUnsigned(request->Version.MinorVersion));

        // Add URL information

        req->Set(v8url, String::New((uint16_t*)request->pRawUrl, request->RawUrlLength));

        // Invoke the JavaScript callback passing event as the only paramater

        Handle<Value> result = httpsys_make_callback(event);
        if (result->IsBoolean() && result->BooleanValue())
        {
            // If the callback response is 'true', proceed to read the request body. 
            // Otherwise request had been paused and will be resumed asynchronously from JavaScript
            // with a call to httpsys_resume.

            if (S_OK != (hr = httpsys_initiate_read_request_body(uv_httpsys)))
            {
                // Initiation failed - notify JavaScript
                httpsys_notify_error(uv_httpsys, HTTPSYS_ERROR_INITIALIZING_READ_REQUEST_BODY, hr);
                httpsys_free(uv_httpsys);
                uv_httpsys = NULL;
            }            
        }
    }
}

HRESULT httpsys_initiate_new_request(HANDLE requestQueue)
{
    HRESULT hr;
    uv_httpsys_t* uv_httpsys = NULL;

    // Create libuv async handle and initialize it

    ErrorIf(NULL == (uv_httpsys = (uv_httpsys_t*)malloc(sizeof(uv_httpsys_t))), ERROR_NOT_ENOUGH_MEMORY);
    RtlZeroMemory(uv_httpsys, sizeof(uv_httpsys_t));
    uv_httpsys->requestQueue = requestQueue;
    CheckError(uv_async_init(uv_default_loop(), &uv_httpsys->uv_async, httpsys_new_request_callback));

    // Allocate initial buffer to receice the HTTP request

    uv_httpsys->bufferSize = initialBufferSize;
    ErrorIf(NULL == (uv_httpsys->buffer = malloc(uv_httpsys->bufferSize)), ERROR_NOT_ENOUGH_MEMORY);
    RtlZeroMemory(uv_httpsys->buffer, uv_httpsys->bufferSize);

    // Initiate async receive of a new request with HTTP.SYS, using the OVERLAPPED
    // associated with the default libuv event loop. 

    hr = HttpReceiveHttpRequest(
        requestQueue,
        HTTP_NULL_ID,
        0,  // TODO: optimize by reading entity body on first async request
        (PHTTP_REQUEST)uv_httpsys->buffer,
        uv_httpsys->bufferSize,
        NULL,
        &uv_httpsys->uv_async.async_req.overlapped);

    ErrorIf(NO_ERROR != hr && ERROR_IO_PENDING != hr, hr);

    return S_OK;

Error:

    httpsys_free(uv_httpsys);
    uv_httpsys = NULL;

    return hr;
}

void httpsys_free_chunks(uv_httpsys_t* uv_httpsys)
{
    if (uv_httpsys->chunks)
    {
        for (int i = 0; i < uv_httpsys->chunkCount; i++)
        {
            if (uv_httpsys->chunks[i].FromMemory.pBuffer)
            {
                free(uv_httpsys->chunks[i].FromMemory.pBuffer);
            }
        }

        free(uv_httpsys->chunks);
        uv_httpsys->chunks = NULL;
        uv_httpsys->chunkCount = 0;
    }
}

void httpsys_free(uv_httpsys_t* uv_httpsys)
{
    if (NULL != uv_httpsys) 
    {
        httpsys_free_chunks(uv_httpsys);

        if (uv_httpsys->response.pReason)
        {
            free((void*)uv_httpsys->response.pReason);
        }

        for (int i = 0; i < HttpHeaderResponseMaximum; i++)
        {
            if (uv_httpsys->response.Headers.KnownHeaders[i].pRawValue)
            {
                free((void*)uv_httpsys->response.Headers.KnownHeaders[i].pRawValue);
            }
        }

        if (uv_httpsys->response.Headers.pUnknownHeaders)
        {
            for (int i = 0; i < uv_httpsys->response.Headers.UnknownHeaderCount; i++)
            {
                if (uv_httpsys->response.Headers.pUnknownHeaders[i].pName)
                {
                    free((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pName);
                }

                if (uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue)
                {
                    free((void*)uv_httpsys->response.Headers.pUnknownHeaders[i].pRawValue);
                }
            }

            free(uv_httpsys->response.Headers.pUnknownHeaders);
        }

        RtlZeroMemory(&uv_httpsys->response, sizeof (uv_httpsys->response));

        if (NULL != uv_httpsys->uv_async.loop)
        {
            uv_unref(uv_httpsys->uv_async.loop);
        }

        if (NULL != uv_httpsys->buffer)
        {
            free(uv_httpsys->buffer);
            uv_httpsys->buffer = NULL;
        }

        free(uv_httpsys);
        uv_httpsys = NULL;
    }
}

void httpsys_read_request_body_callback(uv_async_t* handle, int status)
{
    HTTPSYS_CALLBACK_PREAMBLE
    HRESULT hr;

    // Process async completion

    if (ERROR_HANDLE_EOF == uv_httpsys->uv_async.async_req.overlapped.Internal)
    {
        // End of request body - notify JavaScript

        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_END_REQUEST);
        httpsys_make_callback(event);
    }
    else if (S_OK != uv_httpsys->uv_async.async_req.overlapped.Internal)
    {
        // Async completion failed - notify JavaScript

        httpsys_notify_error(
            uv_httpsys, 
            HTTPSYS_ERROR_READ_REQUEST_BODY, 
            uv_httpsys->uv_async.async_req.overlapped.Internal);
        httpsys_free(uv_httpsys);
        uv_httpsys = NULL;
    }
    else
    {
        // Successful completion - send body chunk to JavaScript as a Buffer

        // Good explanation of native Buffers at 
        // http://sambro.is-super-awesome.com/2011/03/03/creating-a-proper-buffer-in-a-node-c-addon/

        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_REQUEST_BODY);
        ULONG length = uv_httpsys->uv_async.async_req.overlapped.InternalHigh;
        node::Buffer* slowBuffer = node::Buffer::New(length);
        memcpy(node::Buffer::Data(slowBuffer), uv_httpsys->buffer, length);
        Handle<Value> args[] = { slowBuffer->handle_, Integer::New(length), Integer::New(0) };
        Handle<Object> fastBuffer = bufferConstructor->NewInstance(3, args);
        event->Set(v8data, fastBuffer);

        Handle<Value> result = httpsys_make_callback(event);

        if (result->IsBoolean() && result->BooleanValue())
        {
            // If the callback response is 'true', proceed to read more of the request body. 
            // Otherwise request had been paused and will be resumed asynchronously from JavaScript
            // with a call to httpsys_resume.

            if (S_OK != (hr = httpsys_initiate_read_request_body(uv_httpsys)))
            {
                // Initiation failed - notify JavaScript
                httpsys_notify_error(uv_httpsys, HTTPSYS_ERROR_INITIALIZING_READ_REQUEST_BODY, hr);
                httpsys_free(uv_httpsys);
                uv_httpsys = NULL;
            }            
        }       
    }
}

HRESULT httpsys_initiate_read_request_body(uv_httpsys_t* uv_httpsys)
{
    HandleScope handleScope;
    HRESULT hr;

    // Initialize libuv handle representing this async operation

    RtlZeroMemory(&uv_httpsys->uv_async, sizeof(uv_async_t));
    CheckError(uv_async_init(uv_default_loop(), &uv_httpsys->uv_async, httpsys_read_request_body_callback));

    // Initiate async receive of the HTTP request body

    hr = HttpReceiveRequestEntityBody(
        uv_httpsys->requestQueue,
        uv_httpsys->requestId,
        0,  
        uv_httpsys->buffer,
        uv_httpsys->bufferSize,
        NULL,
        &uv_httpsys->uv_async.async_req.overlapped);

    if (ERROR_HANDLE_EOF == hr)
    {
        // End of request body, decrement libuv loop ref count since no async completion will follow
        // and generate JavaScript event
        
        uv_unref(uv_httpsys->uv_async.loop);
        uv_httpsys->uv_async.loop = NULL;
        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_END_REQUEST);
        httpsys_make_callback(event);
    }
    else 
    {
        ErrorIf(NO_ERROR != hr && ERROR_IO_PENDING != hr, hr);
    }

    return S_OK;

Error:

    return hr;
}

Handle<Value> httpsys_init(const Arguments& args)
{
    HandleScope handleScope;

    Handle<Object> options = args[0]->ToObject();

    callback.Dispose();
    callback.Clear();
    callback = Persistent<Function>::New(
        Handle<Function>::Cast(options->Get(String::New("callback"))));
    initialBufferSize = options->Get(String::New("initialBufferSize"))->Int32Value();

    return handleScope.Close(Undefined());
}

Handle<Value> httpsys_listen(const Arguments& args)
{
    HandleScope handleScope;
    HRESULT hr;
    HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_2;
    HTTP_SERVER_SESSION_ID sessionId = HTTP_NULL_ID;
    HTTP_URL_GROUP_ID groupId = HTTP_NULL_ID;
    WCHAR url[MAX_PATH + 1];
    HANDLE requestQueue = NULL;
    HTTP_BINDING_INFO bindingInfo;
    uv_loop_t* loop;
    Handle<Object> result;
    uint32_t* twoint;
    int pendingReadCount;

    // Process arguments

    Handle<Object> options = args[0]->ToObject();

    // Lazy, one-time initialization of HTTP.SYS

    if (!initialized) 
    {
        CheckError(HttpInitialize(
            HttpApiVersion, 
            HTTP_INITIALIZE_SERVER, 
            NULL));
        initialized = 1;
    }

    // Create HTTP.SYS session and associate it with URL group containing the
    // single listen URL. 

    CheckError(HttpCreateServerSession(
        HttpApiVersion, 
        &sessionId, 
        NULL));

    CheckError(HttpCreateUrlGroup(
        sessionId,
        &groupId,
        NULL));

    options->Get(String::New("url"))->ToString()->Write((uint16_t*)url, 0, MAX_PATH);

    CheckError(HttpAddUrlToUrlGroup(
        groupId,
        url,
        0,
        NULL));

    // Create the request queue name by replacing slahes in the URL with _
    // to make it a valid file name.

    for (WCHAR* current = url; *current; current++)
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

    hr = HttpCreateRequestQueue(
        HttpApiVersion,
        url,
        NULL,
        HTTP_CREATE_REQUEST_QUEUE_FLAG_OPEN_EXISTING,
        &requestQueue);

    if (ERROR_FILE_NOT_FOUND == hr)
    {
        // Request queue by that name does not exist yet, try to create it

        CheckError(HttpCreateRequestQueue(
                HttpApiVersion,
                url,
                NULL,
                0,
                &requestQueue));
    }
    else
    {
        CheckError(hr);
    }

    // Bind the request queue with the URL group to enable receiving
    // HTTP traffic on the request queue. 

    RtlZeroMemory(&bindingInfo, sizeof(HTTP_BINDING_INFO));
    bindingInfo.RequestQueueHandle = requestQueue;
    bindingInfo.Flags.Present = 1;

    CheckError(HttpSetUrlGroupProperty(
        groupId,
        HttpServerBindingProperty,
        &bindingInfo,
        sizeof(HTTP_BINDING_INFO)));

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
    ErrorIf(NULL == CreateIoCompletionPort(
        requestQueue,
        loop->iocp,
        (ULONG_PTR)requestQueue,
        0), 
        GetLastError());

    // Initiate reading HTTP requests. The number of pending async requests
    // against HTTP.SYS is specified in the pendingReadCount option.

    pendingReadCount = options->Get(String::New("pendingReadCount"))->Int32Value();
    for (int i = 0; i < pendingReadCount; i++)
    {
        // TODO: address a situation when some new requests fail while others not - cancel them?
        CheckError(httpsys_initiate_new_request(requestQueue));
    }

    // Create an object containing all the handles representing the listener
    // and return it. The object should be passed to httpsys_stop_listen. 
    // The requestQueue member is used to correlate an event with the listener
    // when the callback set through httpsys_set_callback is invoked.

    // The groupId and sessionId are 8 bytes long. Each is repesented as two 
    // 4 byte unsigned integers to leverage efficient V8 representation without
    // allocating heap memory for an External. 

    // TODO: requestQueue representation will need to be fixed on 64-bit systems.

    result = Object::New();
    result->Set(v8requestQueue, Integer::NewFromUnsigned((uint32_t)requestQueue));
    twoint = (uint32_t*)&groupId;
    result->Set(String::New("groupId0"), Integer::NewFromUnsigned(twoint[0]));
    result->Set(String::New("groupId1"), Integer::NewFromUnsigned(twoint[1]));
    twoint = (uint32_t*)&sessionId;
    result->Set(String::New("sessionId0"), Integer::NewFromUnsigned(twoint[0]));
    result->Set(String::New("sessionId1"), Integer::NewFromUnsigned(twoint[1]));

    return handleScope.Close(result);

Error:

    if (HTTP_NULL_ID != groupId)
    {
        HttpCloseUrlGroup(groupId);
        groupId = HTTP_NULL_ID;
    }

    if (NULL != requestQueue)
    {
        HttpCloseRequestQueue(requestQueue);
        requestQueue = NULL;
    }

    if (HTTP_NULL_ID != sessionId)
    {
        HttpCloseServerSession(sessionId);
        sessionId = HTTP_NULL_ID;
    }

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

Handle<Value> httpsys_stop_listen(const Arguments& args)
{
    HandleScope handleScope;
    HRESULT hr;
    uint32_t twoint[2];

    Handle<Object> options = args[0]->ToObject();

    twoint[0] = options->Get(String::New("groupId0"))->Uint32Value();
    twoint[1] = options->Get(String::New("groupId1"))->Uint32Value();
    CheckError(HttpCloseUrlGroup(*(HTTP_URL_GROUP_ID*)&twoint));

    CheckError(HttpCloseRequestQueue(
        (HANDLE)options->Get(v8requestQueue)->Uint32Value()));

    twoint[0] = options->Get(String::New("sessionId0"))->Uint32Value();
    twoint[1] = options->Get(String::New("sessionId1"))->Uint32Value();
    CheckError(HttpCloseServerSession(*(HTTP_SERVER_SESSION_ID*)&twoint));

    return handleScope.Close(Undefined());

Error:

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

Handle<Value> httpsys_resume(const Arguments& args)
{
    HTTPSYS_EXPORT_PREAMBLE;

    CheckError(httpsys_initiate_read_request_body(uv_httpsys));

    return handleScope.Close(Undefined());

Error:

    httpsys_free(uv_httpsys);
    uv_httpsys = NULL;

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

Handle<Value> httpsys_write_headers(const Arguments& args)
{
    HTTPSYS_EXPORT_PREAMBLE;
    Handle<Object> options = args[0]->ToObject();
    String::Utf8Value reason(options->Get(v8reason)); 
    Handle<Object> unknownHeaders;
    Handle<Array> headerNames;
    Handle<String> headerName;
    Handle<Array> knownHeaders;

    // Initialize libuv handle representing this async operation

    RtlZeroMemory(&uv_httpsys->uv_async, sizeof(uv_async_t));
    CheckError(uv_async_init(uv_default_loop(), &uv_httpsys->uv_async, httpsys_write_headers_callback));

    // Set response status code and reason

    uv_httpsys->response.StatusCode = options->Get(v8statusCode)->Uint32Value();
    ErrorIf(NULL == (uv_httpsys->response.pReason = (PCSTR)malloc(reason.length())),
        ERROR_NOT_ENOUGH_MEMORY);
    uv_httpsys->response.ReasonLength = reason.length();
    memcpy((void*)uv_httpsys->response.pReason, *reason, reason.length());

    // Set known headers

    knownHeaders = Handle<Array>::Cast(options->Get(v8knownHeaders));
    for (int i = 0; i < HttpHeaderResponseMaximum; i++)
    {
        Handle<Value> knownHeader = knownHeaders->Get(i);
        if (!knownHeader->IsUndefined())
        {
            String::Utf8Value header(knownHeader);
            ErrorIf(NULL == (uv_httpsys->response.Headers.KnownHeaders[i].pRawValue = 
                (PCSTR)malloc(header.length())),
                ERROR_NOT_ENOUGH_MEMORY);
            uv_httpsys->response.Headers.KnownHeaders[i].RawValueLength = header.length();
            memcpy((void*)uv_httpsys->response.Headers.KnownHeaders[i].pRawValue, 
                *header, header.length());
        }
    }

    // Set unknown headers

    unknownHeaders = options->Get(v8unknownHeaders)->ToObject();
    headerNames = unknownHeaders->GetOwnPropertyNames();
    if (headerNames->Length() > 0)
    {
        ErrorIf(NULL == (uv_httpsys->response.Headers.pUnknownHeaders = 
            (PHTTP_UNKNOWN_HEADER)malloc(headerNames->Length() * sizeof (HTTP_UNKNOWN_HEADER))),
            ERROR_NOT_ENOUGH_MEMORY);
        RtlZeroMemory(uv_httpsys->response.Headers.pUnknownHeaders, 
            headerNames->Length() * sizeof (HTTP_UNKNOWN_HEADER));
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

    // TOOD: support response trailers

    // Initiate async send of the HTTP response headers

    hr = HttpSendHttpResponse(
        uv_httpsys->requestQueue,
        uv_httpsys->requestId,
        HTTP_SEND_RESPONSE_FLAG_MORE_DATA,
        &uv_httpsys->response,
        NULL,
        NULL,
        NULL,
        0,
        &uv_httpsys->uv_async.async_req.overlapped,
        NULL);

    ErrorIf(NO_ERROR != hr && ERROR_IO_PENDING != hr, hr);

    return handleScope.Close(Undefined());

Error:

    httpsys_free(uv_httpsys);
    uv_httpsys = NULL;

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

void httpsys_write_headers_callback(uv_async_t* handle, int status)
{
    HTTPSYS_CALLBACK_PREAMBLE;

    // Process async completion

    if (S_OK != uv_httpsys->uv_async.async_req.overlapped.Internal)
    {
        // Async completion failed - notify JavaScript

        httpsys_notify_error(
            uv_httpsys, 
            HTTPSYS_ERROR_WRITING_HEADERS, 
            uv_httpsys->uv_async.async_req.overlapped.Internal);
        httpsys_free(uv_httpsys);
        uv_httpsys = NULL;
    }
    else
    {
        // Successful completion 

        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_HEADERS_WRITTEN);
        httpsys_make_callback(event);
    }    
}

Handle<Value> httpsys_write_body(const Arguments& args)
{
    HTTPSYS_EXPORT_PREAMBLE;
    Handle<Object> options = args[0]->ToObject();
    ULONG flags;
    Handle<Array> chunks;

    // Initialize libuv handle representing this async operation

    RtlZeroMemory(&uv_httpsys->uv_async, sizeof(uv_async_t));
    CheckError(uv_async_init(uv_default_loop(), &uv_httpsys->uv_async, httpsys_write_body_callback));

    // Determine tha flags

    if (options->Get(v8isLastChunk)->IsBoolean() && options->Get(v8isLastChunk)->BooleanValue())
    {
        flags = 0;
        uv_httpsys->lastChunkSent = 1;
    }
    else
    {
        flags = HTTP_SEND_RESPONSE_FLAG_MORE_DATA;
    }

    // Add chunks of response body if any

    chunks = Handle<Array>::Cast(options->Get(v8chunks));
    if (chunks->Length() > 0)
    {
        httpsys_free_chunks(uv_httpsys);

        ErrorIf(NULL == (uv_httpsys->chunks = 
            (PHTTP_DATA_CHUNK)malloc(chunks->Length() * sizeof(HTTP_DATA_CHUNK))),
            ERROR_NOT_ENOUGH_MEMORY);
        RtlZeroMemory(uv_httpsys->chunks, chunks->Length() * sizeof(HTTP_DATA_CHUNK));
        uv_httpsys->chunkCount = chunks->Length();

        for (unsigned int i = 0; i < uv_httpsys->chunkCount; i++)
        {
            Handle<Object> buffer = chunks->Get(i)->ToObject();
            uv_httpsys->chunks[i].DataChunkType = HttpDataChunkFromMemory;
            ErrorIf(NULL == (uv_httpsys->chunks[i].FromMemory.pBuffer = 
                malloc(node::Buffer::Length(buffer))),
                ERROR_NOT_ENOUGH_MEMORY);
            memcpy(uv_httpsys->chunks[i].FromMemory.pBuffer, node::Buffer::Data(buffer),
                node::Buffer::Length(buffer));
            uv_httpsys->chunks[i].FromMemory.BufferLength = node::Buffer::Length(buffer);
        }
    }

    // Initiate async send of the HTTP response body

    hr = HttpSendResponseEntityBody(
        uv_httpsys->requestQueue,
        uv_httpsys->requestId,
        flags,
        uv_httpsys->chunkCount,
        uv_httpsys->chunks,
        NULL,
        NULL,
        0,
        &uv_httpsys->uv_async.async_req.overlapped,
        NULL);

    ErrorIf(NO_ERROR != hr && ERROR_IO_PENDING != hr, hr);

    return handleScope.Close(Undefined());

Error:

    httpsys_free(uv_httpsys);
    uv_httpsys = NULL;

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

void httpsys_write_body_callback(uv_async_t* handle, int status)
{
    HTTPSYS_CALLBACK_PREAMBLE;

    // Process async completion

    if (S_OK != uv_httpsys->uv_async.async_req.overlapped.Internal)
    {
        // Async completion failed - notify JavaScript

        httpsys_notify_error(
            uv_httpsys, 
            HTTPSYS_ERROR_WRITING_BODY, 
            uv_httpsys->uv_async.async_req.overlapped.Internal);
        httpsys_free(uv_httpsys);
        uv_httpsys = NULL;
    }
    else
    {
        // Successful completion 

        Handle<Object> event = httpsys_create_event(uv_httpsys, HTTPSYS_BODY_WRITTEN);

        if (uv_httpsys->lastChunkSent)
        {
            // Response is completed - clean up resources
            httpsys_free(uv_httpsys);
            uv_httpsys = NULL;
        }

        httpsys_make_callback(event);
    }    
}

void init(Handle<Object> target) 
{
    HandleScope handleScope;

    initialized = 0;

    // Create V8 representation of HTTP verb strings to reuse across requests

    for (int i = 0; i < HttpVerbMaximum; i++)
    {
        if (verbs[i])
        {
            v8verbs[i] = Persistent<String>::New(String::New(verbs[i]));
        }
    }

    // Create V8 representation of HTTP header names to reuse across requests

    for (int i = 0; i < HttpHeaderRequestMaximum; i++)
    {
        if (requestHeaders[i])
        {
            v8httpRequestHeaderNames[i] = Persistent<String>::New(String::New(requestHeaders[i]));
        }
    }

    // Create global V8 strings to reuse across requests

    v8method = Persistent<String>::New(String::NewSymbol("method"));
    v8requestQueue = Persistent<String>::New(String::NewSymbol("requestQueue"));
    v8req = Persistent<String>::New(String::NewSymbol("req"));
    v8httpHeaders = Persistent<String>::New(String::NewSymbol("headers"));
    v8httpVersionMinor = Persistent<String>::New(String::NewSymbol("httpVersionMinor"));
    v8httpVersionMajor = Persistent<String>::New(String::NewSymbol("httpVersionMajor"));
    v8eventType = Persistent<String>::New(String::NewSymbol("eventType"));
    v8code = Persistent<String>::New(String::NewSymbol("code"));
    v8url = Persistent<String>::New(String::NewSymbol("url"));
    v8uv_httpsys = Persistent<String>::New(String::NewSymbol("uv_httpsys"));
    v8data = Persistent<String>::New(String::NewSymbol("data"));
    v8statusCode = Persistent<String>::New(String::NewSymbol("statusCode"));
    v8reason = Persistent<String>::New(String::NewSymbol("reason"));
    v8knownHeaders = Persistent<String>::New(String::NewSymbol("knownHeaders"));
    v8unknownHeaders = Persistent<String>::New(String::NewSymbol("unknownHeaders"));
    v8isLastChunk = Persistent<String>::New(String::NewSymbol("isLastChunk"));
    v8chunks = Persistent<String>::New(String::NewSymbol("chunks"));

    // Capture the constructor function of JavaScript Buffer implementation

    bufferConstructor = Persistent<Function>::New(Handle<Function>::Cast(
        Context::GetCurrent()->Global()->Get(String::New("Buffer")))); 

    // Create exports

    NODE_SET_METHOD(target, "httpsys_init", httpsys_init);
    NODE_SET_METHOD(target, "httpsys_listen", httpsys_listen);
    NODE_SET_METHOD(target, "httpsys_stop_listen", httpsys_stop_listen);
    NODE_SET_METHOD(target, "httpsys_resume", httpsys_resume);
    NODE_SET_METHOD(target, "httpsys_write_headers", httpsys_write_headers);
    NODE_SET_METHOD(target, "httpsys_write_body", httpsys_write_body);
}

NODE_MODULE(httpsys, init);
