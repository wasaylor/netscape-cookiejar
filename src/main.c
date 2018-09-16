#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include "cookiejar.h"
#include "SetCookie.h"

const char *usage = "" \
"cookiejar <option> <Netscape HTTP cookies file>\n" \
"options:\n" \
"  --help Print this dialogue\n" \
"  -h\n" \
"\n" \
"  --json Print the cookies as a null-terminated JSON array of cookie objects to stdout\n" \
"  -j\n" \
"\n" \
"  <Set-Cookie syntax> Set a cookie in the cookies file using the Set-Cookie HTTP header syntax\n" \
"\n";

int main(int argc, char *argv[]) {
  char *path;
  bool json = false, set_cookie = false;
  Cookie new = {0};
  Cookiejar jar;

  if (argc < 3) {
    fputs(usage, stderr);
    return 1;
  }

  path = argv[2];

  if (0 == strcmp(argv[1], "--json") || 0 == strcmp(argv[1], "-j")) {
    /* we're gonna print some JSON */
    json = true;
  } else {
    enum SetCookie_result result;

    /* Set-Cookie syntax */
    switch ((result = SetCookie(argv[1], &new))) {
      case SET_COOKIE_RESULT_OK:
        set_cookie = true;
        break;
      default: /* Any other error */
        fprintf(stderr, "error: Set-Cookie: %s\n", SetCookie_result_strings[result]);
        return 1;
    }
  }

  /* Open the file */
  switch (cookiejar_open(path, &jar)) {
    case COOKIEJAR_RESULT_OPEN_FAILED:
    case COOKIEJAR_RESULT_MAP_FAILED:
      fprintf(stderr, "error: could not load cookies file (errno %i)\n", errno);
      return 1;
    case COOKIEJAR_RESULT_INVALID_FILE:
      fprintf(stderr, "error: invalid cookies file\n");
      return 1;
  }

  if (json) { /* JSON */
    if (!cookiejar_JSON(&jar, stdout)) {
      fprintf(stderr, "error: could not print JSON (errno %i)\n\n", errno);
      return 1;
    }
  } else if (set_cookie) { /* Set-Cookie: */
    int x = -1;
    FILE *fp;

    /* Check if the cookie already exists */
    for (int i = 0; i < jar.n; i++) {
      if (jar.cookies[i].comm)
        continue;

      if (strcmp(jar.cookies[i].Name, new.Name) == 0 &&
        strcmp(jar.cookies[i].Domain, new.Domain) == 0) {
        x = i; /* found it */
        break;
      }
    }

    if (x < 0) { /* Wasn't found */
      x = jar.n; /* Add */
      if (++jar.n > COOKIES_MAX) {}
        /* error */
    }

    /* Set new cookie */
    memcpy(&jar.cookies[x], &new, sizeof(Cookie));

    if ((fp = fopen(path, "w+")) == NULL) {
      return 1;
    }

    if (COOKIEJAR_RESULT_OK != cookiejar_write(&jar, stdout)) {
      return 1;
    }
  }

  cookiejar_finish(&jar);

  return 0;
}
