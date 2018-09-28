#pragma once

#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#define COOKIES_MAX (1000)
#define HTTPONLY_PREFIX "#HttpOnly_"
#define HTTPONLY_PREFIX_LEN (sizeof(HTTPONLY_PREFIX)-1)
#define COOKIE_FORMAT "%s\t%s\t%s\t%s\t%li\t%s\t%s\n"
#define JSON_FORMAT "{ \"name\": \"%s\", \"value\": \"%s\", \"expires\": %li, \"domain\": \"%s\", \"path\": \"%s\", \"secure\": %s, \"httponly\": %s },"

enum cookiejar_result {
  COOKIEJAR_RESULT_OK = 1,
  COOKIEJAR_RESULT_OPEN_FAILED,
  COOKIEJAR_RESULT_MAP_FAILED,
  COOKIEJAR_RESULT_INVALID_FILE,
  COOKIEJAR_RESULT_WRITE_FAILED
};

typedef struct {
  bool evict; /* mark to be deleted */
  bool comm; /* Is it a comment in the file ? (or empty line) */
  bool HttpOnly;
  char *Domain;
  bool flag; /* true is Domain begins with '.' */
  char *Path;
  bool Secure;
  time_t Expires;
  char *Name;
  char *Value;
} Cookie;

typedef struct {
  void *file;
  size_t st_size;
  char *parse;
  Cookie cookies[COOKIES_MAX];
  int n;
} Cookiejar;

bool cookiejar_JSON(Cookiejar *jar, FILE *fp);
enum cookiejar_result cookiejar_finish(Cookiejar *jar);
enum cookiejar_result cookiejar_write(Cookiejar *jar, FILE *fp);
enum cookiejar_result cookiejar_open(char *path, Cookiejar *jar);
