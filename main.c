#include <taihen.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <psp2/net/http.h>
#include <psp2/sysmodule.h>
#include <psp2kern/kernel/rtc.h>

#define SNOOP_MODULE TAI_MAIN_MODULE
#define SCE_HTTP_NID 0xE8F15CDE

#define NEW_SERVER_NAME "activity.ture.fish"
#define ORIGINAL_SERVER_NAME "activity01.ww.np.community.playstation.net"
#define NEW_BASE_URL "https://activity.ture.fish"
#define ORIGINAL_BASE_URL "https://activity0.ww.np.community.playstation.net"

static tai_hook_ref_t load_hook;
static tai_hook_ref_t load2_hook;
static tai_hook_ref_t unload_hook;

static tai_hook_ref_t http_create_request_url_hook;
static SceUID http_create_request_uid;

static tai_hook_ref_t http_create_connection_hook;
static SceUID http_create_connection_uid;

static tai_hook_ref_t http_create_template_hook;
static SceUID http_create_template_uid;

static tai_hook_ref_t http_read_data_hook;
static SceUID http_read_data_uid;

static tai_hook_ref_t http_send_request_hook;
static SceUID http_send_request_uid;

static tai_hook_ref_t http_add_header_hook;
static SceUID http_add_header_uid;

static tai_hook_ref_t http_add_cookie_hook;
static SceUID http_add_cookie_uid;

static tai_hook_ref_t http_set_auth_hook;
static SceUID http_set_auth_uid;


int hook_http_create_request_url(int connId, int method, char *url, SceULong64 contentLength) {
    int ret = TAI_CONTINUE(int, http_create_request_url_hook, connId, method, url, contentLength); // so others get a chance to hook;
    sceClibPrintf("[SnoopItUp] +HTTP_REQUEST (%d) [%d]: %s\n", connId, method, url);

    return ret;
}

int hook_http_create_connection(int tmplId, const char *serverName, const char *scheme, unsigned short port, int enableKeepalive) {
    sceClibPrintf("[SnoopItUp] +HTTP_CONNECTION (%d) [%s] <KEEPALIVE=%d>: %s:%d \n", tmplId, scheme, enableKeepalive, serverName, port);

    return TAI_CONTINUE(int, http_create_connection_hook, tmplId, serverName, scheme, port, enableKeepalive);
}

int hook_http_create_template(const char *userAgent, int httpVer, int autoProxyConf) {
    sceClibPrintf("[SnoopItUp] +HTTP_TEMPLATE: userAgent:'%s' httpVer:%d autoProxyConf:%d\n", userAgent, httpVer, autoProxyConf);

    return TAI_CONTINUE(int, http_create_template_hook, userAgent, httpVer, autoProxyConf);
}

void create_log_path(char *output_buffer, size_t buffer_size, int log_number) {
    // Format the string with the integer appended
    sceClibSnprintf(output_buffer, buffer_size, "ux0:data/snoopitup/log_%d", log_number);
}

int hook_http_read_data(int reqId, void *data, unsigned int size) {
    char path[64];;
    create_log_path(path, 64, reqId);

    SceUID fd = sceIoOpen(path, SCE_O_CREAT | SCE_O_WRONLY | SCE_O_APPEND, 0777);
    if (fd < 0) {
        sceClibPrintf("Unable to open \"%s\" code %x!\n", path, fd);
    }
    else {
        sceIoWrite(fd, data, size);
        sceIoClose(fd);
    }

    sceClibPrintf("[SnoopItUp] +READ_DATA (%d, %d) %s\n", reqId, size, path);

    return TAI_CONTINUE(int, http_read_data_hook, reqId, data, size);
}

int hook_http_send_request(int reqId, const void *postData, unsigned int size) {
    sceClibPrintf("[SnoopItUp] +HTTP_SEND_REQUEST (%d, %d):%s\n", reqId, size, (char*)postData);

    return TAI_CONTINUE(int, http_send_request_hook, reqId, postData, size);
}

int hook_http_add_header(int id, const char *name, const char *value, unsigned int mode) {
    sceClibPrintf("[SnoopItUp] +HEADER (%d, %d) '%s'='%s'\n", id, mode, name, value);

    return TAI_CONTINUE(int, http_add_header_hook, id, name, value, mode);
}

int hook_http_add_cookie(const char *url, const char *cookie, unsigned int cookieLength) {
    sceClibPrintf("[SnoopItUp] +COOKIE (%s, %d) %s\n", url, cookieLength, cookie);

    return TAI_CONTINUE(int, http_add_cookie_hook, url, cookie, cookieLength);
}

int hook_http_set_auth(int id, SceHttpAuthInfoCallback cbfunc, void *userArg) {
    sceClibPrintf("[SnoopItUp] +AUTH (%d)\n", id);

    return TAI_CONTINUE(int, http_set_auth_hook, id, cbfunc, userArg);
}

void hook_http_hooks() {
    sceClibPrintf("[SnoopItUp] HOOKING INTO HTTP!\n");
    http_create_request_uid =
        taiHookFunctionImport(&http_create_request_url_hook, // Output a reference
                    SNOOP_MODULE,           // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0xBD5DA1D0,               // NID specifying sceHttpCreateRequestWithUrl
                    hook_http_create_request_url);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] CREATE REQUEST HOOK 0x%08X\n", http_create_request_uid);

    http_create_connection_uid =
        taiHookFunctionImport(&http_create_connection_hook, // Output a reference
                    SNOOP_MODULE,           // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0xAEB3307E,               // NID specifying sceHttpCreateConnection
                    hook_http_create_connection);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] CREATE CONNECTION HOOK 0x%08X\n", http_create_connection_uid);

    http_create_template_uid =
        taiHookFunctionImport(&http_create_template_hook, // Output a reference
                    SNOOP_MODULE,       // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0x62241DAB,               // NID specifying sceHttpCreateTemplate
                    hook_http_create_template);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] CREATE TEMPLATE HOOK 0x%08X\n", http_create_template_uid);

    http_read_data_uid =
        taiHookFunctionImport(&http_read_data_hook, // Output a reference
                    SNOOP_MODULE,   // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0x7EDE3979,               // NID specifying sceHttpReadData
                    hook_http_read_data);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] READ DATA HOOK 0x%08X\n", http_read_data_uid);

    http_send_request_uid =
        taiHookFunctionImport(&http_send_request_hook, // Output a reference
                    SNOOP_MODULE,           // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0x9CA58B99,               // NID specifying sceHttpReadData
                    hook_http_send_request);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] SEND REQUEST HOOK 0x%08X\n", http_send_request_uid);

    http_add_header_uid =
        taiHookFunctionImport(&http_add_header_hook, // Output a reference
                    SNOOP_MODULE,           // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0x7B51B122,               // NID specifying sceHttpAddRequestHeader
                    hook_http_add_header);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] ADD HEADER HOOK 0x%08X\n", http_add_header_uid);

    http_add_cookie_uid =
        taiHookFunctionImport(&http_add_cookie_hook, // Output a reference
                    SNOOP_MODULE,           // Name of module being hooked
                    SCE_HTTP_NID,               // NID specifying SceHttp
                    0xBEDB988D,               // NID specifying sceHttpAddCookie
                    hook_http_add_cookie);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] ADD COOKIE HOOK 0x%08X\n", http_add_cookie_uid);

    http_set_auth_uid =
    taiHookFunctionImport(&http_set_auth_hook, // Output a reference
                SNOOP_MODULE,           // Name of module being hooked
                SCE_HTTP_NID,               // NID specifying SceHttp
                0xE0A3A88D,               // NID specifying sceHttpSetAuthInfoCallback
                hook_http_set_auth);         // Name of the hook function
    sceClibPrintf("[SnoopItUp] SET AUTH HOOK 0x%08X\n", http_set_auth_uid);
}

void unhook_http_hooks() {
    sceClibPrintf("[SnoopItUp] UNLOADING HTTP!\n");
    if (http_create_request_uid >= 0) {
        taiHookRelease(http_create_request_uid, http_create_request_url_hook);
        http_create_request_uid = -1;
    }

    if (http_create_connection_uid >= 0) {
        taiHookRelease(http_create_connection_uid, http_create_connection_hook);
        http_create_connection_uid = -1;
    }

    if (http_create_template_uid >= 0) {
        taiHookRelease(http_create_template_uid, http_create_template_hook);
        http_create_template_uid = -1;
    }

    if (http_read_data_uid >= 0) {
        taiHookRelease(http_read_data_uid, http_read_data_hook);
        http_read_data_uid = -1;
    }

    if (http_send_request_uid >= 0) {
        taiHookRelease(http_send_request_uid, http_send_request_hook);
        http_send_request_uid = -1;
    }

    if (http_add_header_uid >= 0) {
        taiHookRelease(http_add_header_uid, http_add_header_hook);
        http_add_header_uid = -1;
    }

    if (http_add_cookie_uid >= 0) {
        taiHookRelease(http_add_cookie_uid, http_add_cookie_hook);
        http_add_cookie_uid = -1;
    }

    if (http_set_auth_uid >= 0) {
        taiHookRelease(http_set_auth_uid, http_set_auth_hook);
        http_set_auth_uid = -1;
    }
}

int hook_sysmoduleintopt_load(SceSysmoduleInternalModuleId id, SceSize args, void *argp, const SceSysmoduleOpt *option) {
    int ret;
    ret = TAI_CONTINUE(int, load_hook, id, args, argp, option);
    if (ret >= 0) { // load successful
        switch (id) {
            case SCE_SYSMODULE_INTERNAL_NP_ACTIVITY_NET: 
                hook_http_hooks();
            break;
            // you can consider other loaded modules too here ...
            default:
                break;
        }
    }
    return ret;
}


int hook_sysmoduleint_load(uint32_t id) {
    int ret;
    ret = TAI_CONTINUE(int, load2_hook, id);
    if (ret >= 0) { // load successful
        switch (id) {
            case SCE_SYSMODULE_INTERNAL_NP_ACTIVITY_NET:
                hook_http_hooks();
                break;

            default:
                break;
        }
    }

    return ret;
}

// hook unload module
int hook_sysmodule_unload(uint16_t id) {
    sceClibPrintf("[SnoopItUp] UNLOADING MODULE!\n");
    int ret;
    ret = TAI_CONTINUE(int, unload_hook, id);
    if (ret >= 0) { // unload successful
        switch (id) {
            case SCE_SYSMODULE_HTTP:
                unhook_http_hooks();
                break;

            default:
                break;
        }
    }
    return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp) {
    http_create_request_uid = -1;

    taiHookFunctionImport(&load2_hook,             // Output a reference
                          TAI_MAIN_MODULE,              // Name of module being hooked
                          0x3FCF19D,             // NID specifying SceSysmodule
                          0x2399BF45,             // NID specifying sceSysmoduleLoadModuleInternal
                          hook_sysmoduleint_load);   // Name of the hook function

    taiHookFunctionImport(&load_hook,             // Output a reference
                          TAI_MAIN_MODULE,              // Name of module being hooked
                          0x3FCF19D,             // NID specifying SceSysmodule
                          0xC3C26339,             // NID specifying sceSysmoduleLoadModuleInternalWithArg
                          hook_sysmoduleintopt_load);   // Name of the hook function

    taiHookFunctionImport(&unload_hook,           // Output a reference
                          TAI_MAIN_MODULE,              // Name of module being hooked
                          0x3FCF19D,             // NID specifying SceSysmodule
                          0x31D87805,             // NID specifying sceSysmoduleUnloadModule
                          hook_sysmodule_unload); // Name of the hook function

    sceClibPrintf("[SnoopItUp] Started!\n");

    return SCE_KERNEL_START_SUCCESS;
}


int module_stop(SceSize args, void *argp) {
    return SCE_KERNEL_STOP_SUCCESS;
}
