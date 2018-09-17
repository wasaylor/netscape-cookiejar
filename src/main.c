#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

#include "cookiejar.h"
#include "SetCookie.h"

const char * const usage = "" \
"usage: cookiejar <option> <Netscape HTTP cookie file>\n" \
"options:\n" \
"  <Set-Cookie header> Set a cookie in the cookie file using HTTP Set-Cookie header syntax\n" \
"  -j, --json Print the cookies as a null-terminated JSON array of cookie objects to stdout\n" \
"  -h, --help Print this dialogue\n" \
"\n";

#define EEXIT() \
  cookiejar_finish(&jar); \
  if (fp) fclose(fp); \
  return (1);

int main(int argc, char *argv[]) {
  char *cookies_file_path;
  /* What the program is doing */
  bool json = false,
    set_cookie = false;
  Cookie new = {0}; /* If set_cookie, the new cookie */
  Cookiejar jar = {0}; /* holds cookies file data */
  FILE *fp = NULL; /* Gets open w+ for any changes to cookies */

  if (argc < 3) {
    fputs(usage, stderr);
    EEXIT();
  }

  cookies_file_path = argv[2];

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
        EEXIT();
    }
  }

  /* Load the cookies file */
  switch (cookiejar_open(cookies_file_path, &jar)) {
    case COOKIEJAR_RESULT_OPEN_FAILED:
    case COOKIEJAR_RESULT_MAP_FAILED:
      fprintf(stderr, "error: could not load cookies file (errno %i)\n", errno);
      EEXIT();
    case COOKIEJAR_RESULT_INVALID_FILE:
      fprintf(stderr, "error: invalid cookies file\n");
      EEXIT();
  }

  if (json) { /* JSON */
    if (!cookiejar_JSON(&jar, stdout)) {
      fprintf(stderr, "error: could not print JSON (errno %i)\n\n", errno);
      EEXIT();
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

    if ((fp = fopen(cookies_file_path, "w+")) == NULL) {
      fprintf(stderr, "error: could not open cookies file for write (errno %i)\n", errno);
      EEXIT();
    }

    if (!cookiejar_write(&jar, fp)) {
      fprintf(stderr, "error: could not write cookies file (errno %i)\n", errno);
      EEXIT();
    }

    fclose(fp);
  }

  cookiejar_finish(&jar);

  return 0;
}
