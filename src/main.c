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
"  -e, --evict <Name or *> <Domain or *> <Path or *> Delete a cookie from the cookie file\n" \
"  -j, --json Print the cookies as a null-terminated JSON array of cookie objects to stdout\n" \
"  -h, --help Print this dialogue\n" \
"\n";

#define EEXIT() \
  if (fp) fclose(fp); \
  cookiejar_finish(&jar); \
  return (1);

int exist_cookie(Cookiejar *jar, int index, bool exact, char *Name, char *Domain, char *Path) {
  int i, x;
  bool wn, wd, wp; /* wildcards */

  if (!exact) {
    wn = 0 == strcmp("*", Name);
    wd = 0 == strcmp("*", Domain);
    wp = 0 == strcmp("*", Path);
  } else {
    wn = wd = wp = false;
  }

  for (i = index, x = -1; i < jar->n; i++) {
    int match;

    /* Skip already evicted and non-cookies */
    if (jar->cookies[i].evict || jar->cookies[i].comm)
      continue;

    /* If the user agent receives a new cookie with the same cookie-name,
       domain-value, and path-value as a cookie that it has already stored,
       the existing cookie is evicted and replaced with the new cookie. */
    match = 0;
    if (!wn) match += strcmp(jar->cookies[i].Name, Name);
    if (!wd) match += strcmp(jar->cookies[i].Domain, Domain);
    if (!wp) match += strcmp(jar->cookies[i].Path, Path);

    if (0 == match) {
      x = i; 
      break;
    }
  }

  return x;
}

int main(int argc, char *argv[]) {
  char *cookie_file_path;
  /* What the program is doing */
  bool json = false,
    evict = false,
    set_cookie = false;
  char **evict_av_values = NULL;
  Cookie new = {0}; /* If set_cookie, the new cookie */
  Cookiejar jar = {0}; /* holds cookie file data */
  FILE *fp = NULL; /* Gets open w+ for any changes to cookies */
  int index = 0;

  if (argc < 3) {
    fputs(usage, stderr);
    { EEXIT(); }
  }

  if (0 == strcmp(argv[1], "--json") || 0 == strcmp(argv[1], "-j")) {
    /* we're gonna print some JSON */
    json = true;
  } else if (0 == strcmp(argv[1], "--evict") || 0 == strcmp(argv[1], "-e")) {
    /* Evicting a cookie */
    evict_av_values = &argv[2];
    evict = true;
  } else if (*argv[1] == '-') {
    /* --help or some other unknown option */
    fputs(usage, stderr);
    { EEXIT(); }
  } else { 
    /* Set-Cookie header */
    enum SetCookie_result result;
    
    switch ((result = SetCookie(argv[1], &new))) {
      case SET_COOKIE_RESULT_OK:
        set_cookie = true;
        break;
      default: /* Any other error */
        fprintf(stderr, "error: Set-Cookie: %s\n", SetCookie_result_strings[result]);
        { EEXIT(); }
    }
  }

  /* Should be the last argument */
  cookie_file_path = argv[argc-1]; 

  /* Load the cookie file */
  switch (cookiejar_open(cookie_file_path, &jar)) {
    case COOKIEJAR_RESULT_OPEN_FAILED:
    case COOKIEJAR_RESULT_MAP_FAILED:
      fprintf(stderr, "error: could not load cookie file (errno %i)\n", errno);
      { EEXIT(); }
    case COOKIEJAR_RESULT_INVALID_FILE:
      fprintf(stderr, "error: invalid cookie file\n");
      { EEXIT(); }
  }

  if (json) { /* JSON */
    if (!cookiejar_JSON(&jar, stdout)) {
      fprintf(stderr, "error: could not print JSON (errno %i)\n\n", errno);
      { EEXIT(); }
    }

    cookiejar_finish(&jar);
    return 0;
  }

  if (set_cookie) {
    /* Find cookie to replace */
    if ((index = exist_cookie(&jar, 0, false, new.Name, new.Domain, new.Path)) < 0) {
      index = jar.n; /* Set new */
      if (++jar.n > COOKIES_MAX) {}
        /* error */
    }
    memcpy(&jar.cookies[index], &new, sizeof(Cookie));
  } else if (evict) {
    index = 0;
    /* Find the cookie(s) to evict */
    while ((index = exist_cookie(&jar, index, true,
      evict_av_values[0], evict_av_values[1], evict_av_values[2])) > -1) {
      /* mark */
      jar.cookies[index].evict = true;
    }
  }

  if ((fp = fopen(cookie_file_path, "w+")) == NULL) {
    fprintf(stderr, "error: could not open cookie file for write (errno %i)\n", errno);
    { EEXIT(); }
  }

  if (!cookiejar_write(&jar, fp)) {
    fprintf(stderr, "error: could not write cookie file (errno %i)\n", errno);
    { EEXIT(); }
  }

  fclose(fp);

  cookiejar_finish(&jar);

  return 0;
}
