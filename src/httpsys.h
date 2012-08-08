#ifndef __HTTPSYS_H
#define __HTTPSYS_H

#include <SDKDDKVer.h>
#include <node.h>
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

typedef struct uv_httpsys_s 
{
    uv_async_t uv_async;
    void* buffer;
    int bufferSize;
} uv_httpsys_t;

void https_callback(uv_async_t* handle, int status);
HRESULT httpsys_initiate_new_request(HANDLE requestQueue);

Handle<Value> httpsys_init(const Arguments& args);
Handle<Value> httpsys_listen(const Arguments& args);
Handle<Value> httpsys_stop_listen(const Arguments& args);

void init(Handle<Object> target);

#endif