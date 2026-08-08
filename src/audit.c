// Temporary audit layer made for persistence tests, is likely to be
// fully rewritten when it is implemented for modules other than the
// db connection which is why it is simple and sloppy.

#include "../include/wamble/wamble.h"

static WAMBLE_THREAD_LOCAL WambleAuditSinkFn g_wamble_audit_sink = NULL;
static WAMBLE_THREAD_LOCAL void *g_wamble_audit_sink_userdata = NULL;

void wamble_audit_set_sink(WambleAuditSinkFn sink, void *userdata) {
  g_wamble_audit_sink = sink;
  g_wamble_audit_sink_userdata = userdata;
}

void wamble_audit_emit(const WambleAuditEvent *event) {
  if (!event || !g_wamble_audit_sink)
    return;
  g_wamble_audit_sink(event, g_wamble_audit_sink_userdata);
}
