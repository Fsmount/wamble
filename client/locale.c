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
        "Anonymous",
        "Create Identity",
        "Restore from Backup",
        "Log Out",
        "Back Up Words",
        "Show QR",
        "My Stats",
        "Theme",
        "EN",
        "Join",
        "Review Terms",
        "Accept & Join",
        "You must accept these terms to join %s.",
        "Connected",
        "Reconnecting...",
        "Can't reach server",
        "Retry",
        "No profiles available",
        "Check back later.",
        "No longer available",
        "Done",
        "Restore",
        "Load file",
        "Scan QR",
        "Your 12 words are your identity. Anyone who sees them can become "
        "you.",
        "Write these down somewhere private. Do not share them.",
        "twelve words separated by spaces",
        "Make sure no one else can see your screen.",
        "Those words don't match a valid identity.",
        "No identity found for these words. Did you enter them correctly?",
        "This QR code is your identity. Anyone who scans it can become you.",
        "Show QR Code",
        "Save your progress?",
        "You're playing without an identity. Your score and history will be "
        "lost when you leave.",
        "Not Now",
        "Log out?",
        "You will be removed from this profile and your identity will be "
        "erased from this device. Back up your 12 words first if you "
        "haven't already.",
        "Your identity will be erased from this device. Back up your 12 words "
        "first if you haven't already.",
        "Cancel",
        "Board",
        "Spectate",
        "Predictions",
        "Leaderboard",
        "Stats",
        "All",
        "Standard",
        "960",
        "Spectating #%s",
        "Back to summary",
        "Spectating has ended",
        "Back to play",
        "Can't spectate",
        "Loading games...",
        "No entries yet",
        "No games available for this filter",
        "Illegal move",
        "Moves are disabled",
        "Live",
        "Predict",
        "Checkmate",
        "Stalemate",
        "Draw",
        "Choose promotion",
        "Queen",
        "Rook",
        "Bishop",
        "Knight",
        "Submit",
        "Clear",
        "Predict from here",
        "From #%llu: %s",
        "Board changed",
        "Viewing #%llu",
        "Back to current",
        "No predictions yet",
        "Prediction limit reached for this board",
        "This board has reached its prediction limit",
        "You can view predictions but not submit",
        "pending",
        "correct",
        "incorrect",
        "expired",
        "Score",
        "Rating",
        "Games played",
        "Chess960 games",
        "See all",
        "You: #%u",
        "#%u of %u",
        "#%llu: +%lld",
        "#%llu: -%lld",
        "Something went wrong",
        "Reconnect",
        "Dismiss",
        "Message was corrupted. Try again.",
        "Could not generate secure keys in this browser.",
        "Could not create identity. Try again.",
        "Can't reach server",
        "Could not attach identity. Try again.",
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
