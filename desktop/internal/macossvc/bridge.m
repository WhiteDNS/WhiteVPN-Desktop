// bridge.m — SMAppService and one narrow XPC channel, reached without linking
// anything that needs a macOS 13 SDK.
//
// Two constraints shaped this file:
//
//   - The app builds on CI images whose SDKs predate ServiceManagement's
//     SMAppService header entirely. So the class is found at runtime through
//     the Objective-C runtime, its methods called through objc_msgSend casts,
//     and a missing class simply means "macOS 12 or older" — which the Go side
//     reports honestly rather than crashing on a weak symbol.
//   - The control channel to the daemon must be plain C, because it is the one
//     piece of this boundary that both sides have to get identically right.
//     libxpc predates every SDK this app targets and has not changed shape;
//     NSXPCConnection's typed proxies would need a shared protocol header,
//     which is one more thing two independently signed binaries can disagree
//     about.

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <xpc/xpc.h>
#include <objc/message.h>
#include <objc/runtime.h>

#include <stdlib.h>
#include <string.h>

#include "bridge.h"

// --- small helpers ----------------------------------------------------------

static char *copy_string(NSString *value) {
    if (!value) return NULL;
    return strdup(value.UTF8String);
}

static Class sm_app_service_class(void) {
    static Class cls;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cls = (Class)objc_getClass("SMAppService");
        if (!cls) {
            // Nothing in this process links ServiceManagement, so its classes
            // are not even loaded yet — and objc_getClass only sees what is
            // loaded. Loading it lazily costs one dlopen on the platforms that
            // have it and nothing at all where they do not.
            void *framework = dlopen(
                "/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement",
                RTLD_LAZY | RTLD_LOCAL);
            if (framework) {
                cls = (Class)objc_getClass("SMAppService");
            }
        }
    });
    return cls;
}

static id service_for_plist(const char *plist_name, char **err) {
    // Deliberately NO autorelease pool here: the service handle this returns
    // is an autoreleased object, and a pool in this frame would drain it on
    // the way out, handing the caller a dangling pointer. The exported entry
    // points below each open one pool that covers both this call and every
    // use of its result.
    Class cls = sm_app_service_class();
    if (!cls) {
        if (err) *err = strdup("SMAppService is unavailable (macOS 13 or newer needed)");
        return nil;
    }
    // Runtime-called selectors cannot be checked by the compiler, and one
    // wrong name would otherwise raise an NSException straight through the
    // process. Caught here, a mistake becomes an ordinary error instead.
    //
    // The daemon factory has shipped under two names — the header's
    // daemonWithPlistName: and the runtime's daemonServiceWithPlistName: — so
    // both are tried before giving up.
    @try {
        id (*make)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
        NSString *name = [NSString stringWithUTF8String:plist_name];
        SEL selectors[2] = {
            sel_registerName("daemonWithPlistName:"),
            sel_registerName("daemonServiceWithPlistName:"),
        };
        for (unsigned int i = 0; i < 2; i++) {
            if ([cls respondsToSelector:selectors[i]]) {
                return make((id)cls, selectors[i], name);
            }
        }
        if (err) *err = strdup("SMAppService has no daemon factory this build recognises");
        return nil;
    } @catch (NSException *exception) {
        if (err) *err = copy_string(exception.reason);
        return nil;
    }
}

// --- availability -----------------------------------------------------------

int wv_available(void) { return sm_app_service_class() != nil ? 1 : 0; }

// --- registration -----------------------------------------------------------

int wv_sm_status(const char *plist_name, char **out, char **err) {
    @autoreleasepool {
    id service = service_for_plist(plist_name, err);
    if (!service) {
        if (!*err) *err = strdup("cannot create the service handle");
        return -1;
    }
    NSInteger (*status_of)(id, SEL) = (NSInteger (*)(id, SEL))objc_msgSend;
    // 0 notRegistered, 1 enabled, 2 requiresApproval, 3 notFound. The enum is
    // stable API; the numbers are spelled out here because there is no header
    // to name them for us.
    @try {
        switch (status_of(service, sel_registerName("status"))) {
            case 0: *out = strdup("notRegistered");    return 0;
            case 1: *out = strdup("enabled");          return 0;
            case 2: *out = strdup("requiresApproval"); return 0;
            case 3: *out = strdup("notFound");         return 0;
            default: *err = strdup("unknown registration status"); return -1;
        }
    } @catch (NSException *exception) {
        *err = copy_string(exception.reason);
        return -1;
    }
    }
}

static int change_registration(const char *plist_name, SEL action, char **err) {
    @autoreleasepool {
    id service = service_for_plist(plist_name, err);
    if (!service) {
        if (!*err) *err = strdup("cannot create the service handle");
        return -1;
    }
    BOOL (*perform)(id, SEL, NSError **) = (BOOL (*)(id, SEL, NSError **))objc_msgSend;
    @try {
        NSError *failure = nil;
        if (!perform(service, action, &failure)) {
            NSString *detail = failure.localizedDescription ?: @"registration was refused without a reason";
            *err = copy_string(detail);
            return -1;
        }
        return 0;
    } @catch (NSException *exception) {
        *err = copy_string(exception.reason);
        return -1;
    }
    }
}

int wv_sm_register(const char *plist_name, char **err) {
    return change_registration(plist_name, sel_registerName("registerAndReturnError:"), err);
}

int wv_sm_unregister(const char *plist_name, char **err) {
    return change_registration(plist_name, sel_registerName("unregisterAndReturnError:"), err);
}

// --- control channel --------------------------------------------------------

// describe_xpc_error turns a transport failure into a sentence. XPC error
// objects are not NSError; they are compared against the stable constants and
// anything unknown gets the honest default.
static char *describe_xpc_error(xpc_object_t event) {
    if (event == XPC_ERROR_CONNECTION_INVALID) {
        return strdup("the privileged helper is not running");
    }
    if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
        return strdup("the privileged helper went away mid-request");
    }
    return strdup("the privileged helper could not be reached");
}

char *wv_xpc_call(const char *service, const char *method, const char *argument,
                  double timeout_seconds, char **err) {
    if (timeout_seconds <= 0) timeout_seconds = 5;

    xpc_connection_t connection = xpc_connection_create_mach_service(service, NULL, 0);
    if (!connection) {
        *err = strdup("could not open a channel to the privileged helper");
        return NULL;
    }

    // A client only ever receives inbound connections it did not ask for here;
    // nothing carries our answer, so the handler just notes closure.
    __block int closed = 0;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) closed = 1;
    });
    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "method", method);
    if (argument && argument[0]) {
        xpc_dictionary_set_string(message, "argument", argument);
    }

    // The reply arrives on whatever thread the queue hands it. One flag keeps
    // the late transport-error delivery (after a timeout, or after a real
    // answer) from overwriting what we already decided.
    __block xpc_object_t reply = NULL;
    __block char *failure = NULL;
    __block int settled = 0;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_queue_t replies = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
    xpc_connection_send_message_with_reply(connection, message, replies, ^(xpc_object_t event) {
        xpc_type_t kind = xpc_get_type(event);
        if (!settled) {
            settled = 1;
            if (kind == XPC_TYPE_DICTIONARY) {
                reply = xpc_retain(event);
            } else {
                failure = describe_xpc_error(event);
            }
        }
        dispatch_semaphore_signal(done);
    });

    int64_t deadline = (int64_t)(timeout_seconds * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, deadline)) != 0) {
        // Cancelling makes the pending handler deliver a transport error, so
        // this thread joins promptly instead of leaking one behind its own
        // deadline.
        xpc_connection_cancel(connection);
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    }
    dispatch_release(done);

    char *result = NULL;
    if (!settled) {
        *err = strdup("the privileged helper never answered");
    } else if (failure) {
        *err = failure;
    } else if (reply) {
        const char *error = xpc_dictionary_get_string(reply, "error");
        const char *payload = xpc_dictionary_get_string(reply, "reply");
        if (error && error[0]) {
            *err = strdup(error);
        } else if (payload) {
            result = strdup(payload);
        } else {
            *err = strdup("the privileged helper sent an empty reply");
        }
    }

    if (reply) xpc_release(reply);
    (void)closed;
    xpc_release(message);
    xpc_release(connection);
    return result;
}
