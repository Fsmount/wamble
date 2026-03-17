#include "wamble/wamble_client.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  const char *locale;
  const char *texts[WAMBLE_CLIENT_TEXT_COUNT];
} WambleClientLocaleCatalog;

static const WambleClientLocaleCatalog locale_catalogs[] = {{
    "en",
    {
        "Create Session",
        "Attach",
        "Back",
        "session required",
        "session ready",
        "identity ready",
        "Mnemonic",
        "Public Key",
        "connected to %s",
        "disconnected",
        "connecting...",
        "anonymous",
        "Create Identity",
        "Restore",
        "Logout",
        "Save these 12 words. They are your key.",
        "Enter your 12 words",
        "Invalid mnemonic",
        "Save your progress",
        "White to move",
        "Black to move",
        "Illegal move",
        "Board",
        "Leaderboard",
        "Stats",
        "Spectate",
        "Spectating #%s",
        "Leave",
        "Predictions",
        "Submit",
        "Server",
        "No profiles available",
        "Could not reach server",
        "Retry",
        "Done",
        "Dismiss",
        "Join",
        "Score",
        "Games",
        "Chess960",
        "Player",
        "Theme",
        "Rating",
        "Terms",
        "Terms of Service",
        "Close",
        "Clear Parent",
        "All",
        "Standard",
        "Available profiles for this deployment",
        "not stored in browser",
        "Replying to: root",
        "Replying to: #%llu",
        "Terms unavailable for this profile.",
        "Terms payload is too large to display.",
        "Could not determine deployment host",
        "Could not attach identity",
        "Loading games...",
        "No games available for this filter",
        "Loading...",
        "No entries yet",
        "You: #%u",
        "pending",
        "correct",
        "incorrect",
        "expired",
        "unknown",
        "No predictions yet",
        "Checking...",
        "Unavailable",
        "Loading terms...",
        "Next half-move",
        "Current position",
        "Clear selection",
        "Previewing #%llu",
        "Selected half-move: %s",
        "Choose promotion",
        "Queen",
        "Rook",
        "Bishop",
        "Knight",
        "Choose the next half-move on the board or use a custom UCI.",
        "Selected UCI: %s",
        "Custom UCI",
        "Optional for policy-allowed predictions beyond the previewed move.",
        "e2e4",
        "Use custom UCI",
        "Invalid UCI",
        "Loading predictions...",
        "Request failed",
        "Discarded fragmented message with bad hash",
        "Failed to decode fragmented server payload",
        "Loaded a legacy stored identity for this tab and cleared browser "
        "storage.",
        "Removed an invalid stored mnemonic from browser storage.",
        "Failed to gather browser entropy",
        "Failed to generate identity",
        "word1 word2 ...",
    },
}};

static const WambleClientLocaleCatalog *
locale_catalog_find(const char *locale) {
  if (!locale || !*locale)
    return &locale_catalogs[0];
  for (size_t i = 0; i < sizeof(locale_catalogs) / sizeof(locale_catalogs[0]);
       i++) {
    size_t base_len = strlen(locale_catalogs[i].locale);
    if (strncmp(locale, locale_catalogs[i].locale, base_len) == 0 &&
        (locale[base_len] == '\0' || locale[base_len] == '-' ||
         locale[base_len] == '_')) {
      return &locale_catalogs[i];
    }
  }
  return &locale_catalogs[0];
}

const char *wamble_client_locale_text(const char *locale,
                                      WambleClientTextId id) {
  const WambleClientLocaleCatalog *catalog = locale_catalog_find(locale);
  if (!catalog || id < 0 || id >= WAMBLE_CLIENT_TEXT_COUNT)
    return NULL;
  return catalog->texts[id];
}

int wamble_client_locale_write(const char *locale, WambleClientTextId id,
                               char *out, size_t out_size) {
  const char *text = wamble_client_locale_text(locale, id);
  if (!text || !out || out_size == 0)
    return -1;
  {
    int n = snprintf(out, out_size, "%s", text);
    if (n < 0 || (size_t)n >= out_size)
      return -1;
  }
  return 0;
}

int wamble_client_locale_format(const char *locale, WambleClientTextId id,
                                char *out, size_t out_size, ...) {
  const char *text = wamble_client_locale_text(locale, id);
  va_list ap;
  int n;
  if (!text || !out || out_size == 0)
    return -1;
  va_start(ap, out_size);
  n = vsnprintf(out, out_size, text, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= out_size)
    return -1;
  return 0;
}
