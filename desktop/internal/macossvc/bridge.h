// bridge.h — the C surface the Go side talks to.
//
// Everything here is deliberately boring: strings in, ints out, errors as
// malloc'd UTF-8 that the caller frees. The interesting constraints are inside
// bridge.m: no link-time dependency on any macOS 13 framework, because this
// compiles on machines whose SDKs predate SMAppService entirely.

#ifndef WHITEVPN_MACOSSVC_BRIDGE_H
#define WHITEVPN_MACOSSVC_BRIDGE_H

// wv_available reports whether SMAppService exists on this OS at all
// (macOS 13+). Everything else returns an error when it does not, but this is
// cheap enough to gate on directly.
int wv_available(void);

// wv_sm_status writes one of "notRegistered", "enabled", "requiresApproval",
// "notFound" into *out. Returns 0 on success, -1 with *err set otherwise.
int wv_sm_status(const char *plist_name, char **out, char **err);

// wv_sm_register enables the daemon described by the named plist inside this
// app's bundle. Returns 0 on success, -1 with *err set otherwise.
int wv_sm_register(const char *plist_name, char **err);

// wv_sm_unregister disables it again.
int wv_sm_unregister(const char *plist_name, char **err);

// wv_xpc_call sends {"method": method, "argument": argument} to the named mach
// service and returns the reply payload as a malloc'd string (caller frees).
// A non-dictionary reply or a transport error is reported through *err.
char *wv_xpc_call(const char *service, const char *method, const char *argument,
                  double timeout_seconds, char **err);

#endif /* WHITEVPN_MACOSSVC_BRIDGE_H */
