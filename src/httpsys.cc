#include "httpsys.h"

using namespace v8;

int initialized;
int initialBufferSize;
Persistent<Function> callback;

void https_callback(uv_async_t* handle, int status)
{
	uv_httpsys_t* uv_httpsys = CONTAINING_RECORD(handle, uv_httpsys_t, uv_async);
    printf("in native callback!\n");
}

HRESULT httpsys_initiate_new_request(HANDLE requestQueue)
{
    HRESULT hr;
    uv_httpsys_t* uv_httpsys = NULL;

    // Create libuv async handle and initialize it

    ErrorIf(NULL == (uv_httpsys = (uv_httpsys_t*)malloc(sizeof(uv_httpsys_t))), ERROR_NOT_ENOUGH_MEMORY);
    RtlZeroMemory(uv_httpsys, sizeof(uv_httpsys_t));
    CheckError(uv_async_init(uv_default_loop(), &uv_httpsys->uv_async, https_callback));

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

    if (NULL != uv_httpsys) 
    {
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

    // Associate the request queue handle with the IO completion port 
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
    result->Set(String::New("requestQueue"), Integer::NewFromUnsigned((uint32_t)requestQueue));
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
        (HANDLE)options->Get(String::New("requestQueue"))->Uint32Value()));

    twoint[0] = options->Get(String::New("sessionId0"))->Uint32Value();
    twoint[1] = options->Get(String::New("sessionId1"))->Uint32Value();
    CheckError(HttpCloseServerSession(*(HTTP_SERVER_SESSION_ID*)&twoint));

    return handleScope.Close(Undefined());

Error:

    return handleScope.Close(ThrowException(Int32::New(hr)));
}

void init(Handle<Object> target) 
{
    initialized = 0;
    NODE_SET_METHOD(target, "httpsys_init", httpsys_init);
    NODE_SET_METHOD(target, "httpsys_listen", httpsys_listen);
    NODE_SET_METHOD(target, "httpsys_stop_listen", httpsys_stop_listen);
}

NODE_MODULE(httpsys, init);
