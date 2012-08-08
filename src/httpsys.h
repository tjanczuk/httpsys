#ifndef __HTTPSYS_H
#define __HTTPSYS_H

// TODO: implement httpsys_resume

#include <SDKDDKVer.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <uv.h>
#include <http.h>

using namespace v8;

#pragma comment(lib, "httpapi.lib")

#define ErrorIf(expr, hresult)    \
    if (expr)                     \
    {                             \
        hr = hresult;             \
        goto Error;               \
    }

#define CheckError(hresult)       \
    {                             \
        HRESULT tmp_hr = hresult; \
        if (S_OK != tmp_hr)       \
        {                         \
            hr = tmp_hr;          \
            goto Error;           \
        }                         \
    }

typedef struct uv_httpsys_s {
    uv_async_t uv_async;
    HANDLE requestQueue;
    HTTP_REQUEST_ID requestId;
    void* buffer;
    int bufferSize;
} uv_httpsys_t;

typedef enum {
    HTTPSYS_ERROR_INITIALIZING_REQUEST = 1,
    HTTPSYS_ERROR_NEW_REQUEST,
    HTTPSYS_NEW_REQUEST,
    HTTPSYS_ERROR_INITIALIZING_READ_REQUEST_BODY,
    HTTPSYS_END_REQUEST,
    HTTPSYS_ERROR_READ_REQUEST_BODY,
    HTTPSYS_REQUEST_BODY
} uv_httpsys_event_type;

Handle<Object> httpsys_create_event(uv_httpsys_t* uv_httpsys, int eventType);
Handle<Value> httpsys_notify_error(uv_httpsys_t* uv_httpsys, uv_httpsys_event_type errorType, int code);
void httpsys_free(uv_httpsys_t* uv_httpsys);

void httpsys_new_request_callback(uv_async_t* handle, int status);
HRESULT httpsys_initiate_new_request(HANDLE requestQueue);

void httpsys_read_request_body_callback(uv_async_t* handle, int status);
HRESULT httpsys_initiate_read_request_body(uv_httpsys_t* uv_httpsys);

Handle<Value> httpsys_init(const Arguments& args);
Handle<Value> httpsys_listen(const Arguments& args);
Handle<Value> httpsys_stop_listen(const Arguments& args);

void init(Handle<Object> target);

#endif