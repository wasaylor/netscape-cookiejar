#pragma once

#include "cookiejar.h"

#define SET_COOKIE_HEADER "Set-Cookie:"
#define SET_COOKIE_HEADER_LEN (sizeof(SET_COOKIE_HEADER)-1)
#define SET_COOKIE_MAX_AV (8) /* includes up to 1 extension */

enum SetCookie_av {
  SET_COOKIE_AV_EXPIRES = 1,
  SET_COOKIE_AV_MAX_AGE,
  SET_COOKIE_AV_DOMAIN,
  SET_COOKIE_AV_PATH,
  SET_COOKIE_AV_SECURE,
  SET_COOKIE_AV_HTTPONLY,
  SET_COOKIE_AV_EXTENSION
};

enum SetCookie_result {
  SET_COOKIE_RESULT_OK = 1,
  SET_COOKIE_RESULT_INVALID_SYNTAX,
  SET_COOKIE_RESULT_AV_EXCEEDED,
  SET_COOKIE_RESULT_PERFER_MAX_AGE,
  SET_COOKIE_RESULT_MISSING_MAX_AGE,
  SET_COOKIE_RESULT_MISSING_DOMAIN,
  SET_COOKIE_RESULT_MISSING_PATH
};
extern const char * const SetCookie_result_strings[];

enum SetCookie_result SetCookie(char *header, Cookie *out);
