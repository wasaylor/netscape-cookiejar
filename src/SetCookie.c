#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "SetCookie.h"
#include "cookiejar.h"

const char * const SetCookie_result_strings[] = {
  NULL,
  "OK",
  "invalid syntax - see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
  "too many directives",
  "use Max-Age instead",
  "missing Max-Age directive",
  "missing Domain directive",
  "missing Path directive"
};

/* allowed characters in the name portion of the <cookie-name>=<cookie-value> directive for Set-Cookie:
   https://tools.ietf.org/html/rfc2616#section-2.2 */
bool is_rfc2616_token(char *str) {
  char c;

  while ((c = *str++))
    if ((c >= 0 && c <= 31) || c == 127 || strchr("()<>@,;:\\\"/[]?={} \t", c) != NULL)
      return false;

  return true;
}

/* allowed characters in the value portion of the <cookie-name>=<cookie-value> directive for Set-Cookie:
   https://tools.ietf.org/html/rfc6265#section-4.1.1
   */
bool is_rfc6265_cookie_octet(char *str) {
  char c;

  while ((c = *str++))
    if (!(c == '\x21' ||
        (c >= '\x23' && c <= '\x2b') ||
        (c >= '\x2d' && c <= '\x3a') ||
        (c >= '\x3c' && c <= '\x5b') ||
        (c >= '\x5d' && c <= '\x7e')))
      return false;

  return true;
}

enum SetCookie_result SetCookie(char *header, Cookie *c) {
  char *string;
  struct {
    char *name;
    char *value;
  } pair;
  struct { 
    enum SetCookie_av av;
    char *value;
  } av[SET_COOKIE_MAX_AV];
  int numav;
  long delta_seconds;
  bool has_expires = false, set_max_age = false;

  /* Syntax */
  if (header != strstr(header, SET_COOKIE_HEADER))
    return SET_COOKIE_RESULT_INVALID_SYNTAX;

  if (*(header + SET_COOKIE_HEADER_LEN) != ' ') /* SP */
    return SET_COOKIE_RESULT_INVALID_SYNTAX;

  /* cookie-string
     this becomes what we parse */
  string = header + SET_COOKIE_HEADER_LEN + 1;
  
  /* <cookie-name> */
  pair.name = string;

  if ((string = strchr(string, '=')) == NULL) /* "=" */
    return SET_COOKIE_RESULT_INVALID_SYNTAX;
  *string++ = '\0';

  /* <cookie-value> */
  pair.value = string;

  /* cookie-av */
  for (numav = 0; *string && numav < SET_COOKIE_MAX_AV + 1; numav++) {
    if ((string = strchr(string, ';')) == NULL) /* move to the next av */
      break; /* no more directives */

    /* ";" SP */
    if (!(string[0] == ';' && string[1] == ' '))
      return SET_COOKIE_RESULT_INVALID_SYNTAX;
    *string++ = '\0';
    *string++ = '\0';

    /* before we start parsing the av, check limits */
    if (SET_COOKIE_MAX_AV == numav)
      return SET_COOKIE_RESULT_AV_EXCEEDED;

    /* cookie-av */
    if (strcasestr(string, "Expires=") == string) {
      string += 8;
      av[numav].av = SET_COOKIE_AV_EXPIRES;
      av[numav].value = string;
    } else if (strcasestr(string, "Max-Age=") == string) {
      string += 8;
      av[numav].av = SET_COOKIE_AV_MAX_AGE;
      av[numav].value = string;
    } else if (strcasestr(string, "Domain=") == string) {
      string += 7;
      av[numav].av = SET_COOKIE_AV_DOMAIN;
      av[numav].value = string;
    } else if (strcasestr(string, "Path=") == string) {
      string += 5;
      av[numav].av = SET_COOKIE_AV_PATH;
      av[numav].value = string;
    } else if (strcasestr(string, "Secure") == string) {
      string += 6;
      av[numav].av = SET_COOKIE_AV_SECURE;
      av[numav].value = NULL;
    } else if (strcasestr(string, "HttpOnly") == string) {
      string += 8;
      av[numav].av = SET_COOKIE_AV_HTTPONLY;
      av[numav].value = NULL;
    } else { 
      av[numav].av = SET_COOKIE_AV_EXTENSION;
      av[numav].value = string;
    } 
  }

  /* check and set the cookie name and value */
  if (!is_rfc2616_token(pair.name) || *pair.name == '\0')
    return SET_COOKIE_RESULT_INVALID_SYNTAX;
  c->Name = pair.name;

  if (*pair.value == '\"') { /* DQUOTE *cookie-octet DQUOTE */
    char *ldquote;

    ldquote = strrchr(pair.value + 1, '\"');
    fputs(ldquote, stderr);
    if (!ldquote || *(ldquote + 1) != '\0') /* doesn't end with a DQUOTE */
      return SET_COOKIE_RESULT_INVALID_SYNTAX;

    /* move past first DQUOTE and null-terminate last DQUOTE */
    ++pair.value;
    *ldquote = '\0';
    fputs(pair.value, stderr);
  }

  if (!is_rfc6265_cookie_octet(pair.value) || *pair.value == '\0')
    return SET_COOKIE_RESULT_INVALID_SYNTAX;
  c->Value = pair.value;

  /* set the directives */
  while (numav--) {
    switch (av[numav].av) {
      case SET_COOKIE_AV_EXPIRES:
        has_expires = true;
        break;
      case SET_COOKIE_AV_MAX_AGE:
        if ((delta_seconds = atol(av[numav].value)) > 0)
          c->Expires = time(NULL) + delta_seconds;
        else
          c->Expires = (time_t)0;

        set_max_age = true;
        break;
      case SET_COOKIE_AV_DOMAIN:
        c->Domain = av[numav].value;
        break;
      case SET_COOKIE_AV_PATH:
        c->Path = av[numav].value;
        break;
      case SET_COOKIE_AV_SECURE:
        c->Secure = true;
        break;
      case SET_COOKIE_AV_HTTPONLY:
        c->HttpOnly = true;
        break;
      /* default:
        fprintf(stderr, "warning: directive \"%s\" is not supported\n", av[numav].value); */
    }
  }
  string = NULL; /* fin */

  /* If a cookie has both the Max-Age and the Expires attribute, the Max-
     Age attribute has precedence and controls the expiration date of the
     cookie. */
  if (has_expires && !set_max_age)
    return SET_COOKIE_RESULT_PERFER_MAX_AGE;
  if (!set_max_age)
    return SET_COOKIE_RESULT_MISSING_MAX_AGE;

  /* Must have a domain */
  if (!c->Domain || *c->Domain == '\0')
    return SET_COOKIE_RESULT_MISSING_DOMAIN;

  if (*c->Domain == '.')
    c->flag = true;

  /* Must have a path */
  if (!c->Path)
    return SET_COOKIE_RESULT_MISSING_PATH;

  return SET_COOKIE_RESULT_OK;
}
