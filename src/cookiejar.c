#include <sys/stat.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "cookiejar.h"

bool ptob(char *p, bool *out) {
#ifdef COOKIEJAR_FAST_BOOLS
  *out = *p == 'T';
#else
  if (strcmp(p, "TRUE") == 0)
    *out = true;
  else if (strcmp(p, "FALSE") == 0)
    *out = false;
  else
    return false;
#endif
  return true;
}

size_t parse_remain(Cookiejar *jar) {
  ptrdiff_t d;

  if (jar->parse == NULL)
    return 0;

  d = (jar->parse - (char*)jar->file);
  return (jar->st_size - (size_t)d);
}

/* Take a bite out of line in the cookiejar and make the expected termination NULL and
   return the bite (piece.)
   eol - Expect EOL, otherwise expects a TAB */
char *bite(bool eol, Cookiejar *jar) {
  size_t rem;
  char *p, *term;

  if ((rem = parse_remain(jar)) < 1)
    return NULL; /* ran out of file */

  p = jar->parse; /* piece to return */

  /* find the terminator */
  if ((term = memchr(p, eol ? '\n' : '\t', rem))) {
    /* terminator was found, make it \0 so the piece becomes a string */
    *term = '\0';
    jar->parse = term + 1; /* continue parse after the term */

    return p; /* return the piece */
  } else {
    return NULL; /* no piece */
  }
}

bool cookiejar_parse_do(Cookiejar *jar) {
  size_t rem;

  while ((rem = parse_remain(jar)) > 0 && jar->n < COOKIES_MAX) {
    Cookie *c;
    char *p[7];

    c = &jar->cookies[jar->n];
    memset(c, 0, sizeof(Cookie));

    if (*jar->parse == '\n' || *jar->parse == '#') {
      if (strnstr(jar->parse, HTTPONLY_PREFIX, rem) == jar->parse) {
        /* HttpOnly cookies are hacked in as comments */
        jar->parse += HTTPONLY_PREFIX_LEN;

        c->HttpOnly = true;
        /* fall into standard Cookie logic below */
      } else {
        /* True comment or empty line */
        if ((p[0] = bite(true, jar)) == NULL)
          return false;

        c->comm = true;
        c->Value = p[0];
        ++jar->n;

        continue; /* no need to go any futher */
      }
    }

    /* Now we're parsing a _real_ Cookie - all 7 pieces */
    for (int i = 0; i < 7; i++) {
      if ((p[i] = bite(i == 6, jar)) == NULL || *p[i] == '\0')
        return false;
    }

    c->Domain = p[0];
    if (!ptob(p[1], &c->flag))
      return false;
    c->Path = p[2];
    if (!ptob(p[3], &c->Secure))
      return false;
    c->Expires = (time_t)atol(p[4]);
    c->Name = p[5];
    c->Value = p[6];
    ++jar->n;
  } 

  return true;
}

/* prints a null terminated JSON array of cookie objects to a FILE
   returns false if any write fails */
bool cookiejar_JSON(Cookiejar *jar, FILE *fp) {
  int printed;

  if (fputc('[', fp) == EOF)
    return false;

  for (int i = 0; i < jar->n; i++) {
    if (jar->cookies[i].evict || jar->cookies[i].comm)
      continue;

    printed = fprintf(fp,
      JSON_FORMAT,
      jar->cookies[i].Name,
      jar->cookies[i].Value,
      jar->cookies[i].Expires,
      jar->cookies[i].Domain,
      jar->cookies[i].Path,
      jar->cookies[i].Secure ? "true" : "false",
      jar->cookies[i].HttpOnly ? "true" : "false");

    if (printed <= 0)
      return false;
  }

  printed = fputs("null]", fp);

  if (printed <= 0)
    return false;

  return true;
}

enum cookiejar_result cookiejar_finish(Cookiejar *jar) {
  if (jar->file)
    munmap(jar->file, jar->st_size);

  memset(jar, 0, sizeof(Cookiejar));

  return COOKIEJAR_RESULT_OK;
}

enum cookiejar_result cookiejar_write(Cookiejar *jar, FILE *fp) {
  for (int i = 0; i < jar->n; i++) {
    char *format;
    int printed;

    if (jar->cookies[i].evict) /* deleted */
      continue;

    if (jar->cookies[i].comm) { /* Comment / empty line */
      printed = fprintf(fp, "%s\n",
        jar->cookies[i].Value);

      if (printed <= 0)
        return COOKIEJAR_RESULT_WRITE_FAILED;

      continue;
    }

    if (jar->cookies[i].HttpOnly)
      format = HTTPONLY_PREFIX COOKIE_FORMAT;
    else
      format = COOKIE_FORMAT;

    printed = fprintf(fp, (const char*)format,
      jar->cookies[i].Domain,
      jar->cookies[i].flag ? "TRUE" : "FALSE",
      jar->cookies[i].Path,
      jar->cookies[i].Secure ? "TRUE" : "FALSE",
      jar->cookies[i].Expires,
      jar->cookies[i].Name,
      jar->cookies[i].Value);

     if (printed <= 0)
        return COOKIEJAR_RESULT_WRITE_FAILED;
  }

  return COOKIEJAR_RESULT_OK;
}

/* Loads a Cookiejar from a netscape cookies file */
enum cookiejar_result cookiejar_open(char *path, Cookiejar *jar) {
  int fd;
  struct stat s;
  void *file;

  if ((fd = open(path, O_RDONLY)) < 0)
    return COOKIEJAR_RESULT_OPEN_FAILED;

  if (fstat(fd, &s) < 0) {
    /* Failed to stat the file */
    close(fd);
    return COOKIEJAR_RESULT_OPEN_FAILED;
  }

  if (s.st_size <= 0) {
    /* Empty file
       */
    close(fd);

    jar->file = NULL;
    jar->st_size = 0;
    jar->parse = NULL;
    jar->n = 0;

    return COOKIEJAR_RESULT_OK;
  }

  /* Map the cookies file into memory */
  file = mmap(
    NULL,
    s.st_size, /* whole file */
    PROT_READ|PROT_WRITE, /* read and write the memory */
    MAP_FILE|MAP_PRIVATE, /* do not copy changes to file */
    fd,
    0);
  close(fd); /* don't need this anymore */

  if (MAP_FAILED == file)
    return COOKIEJAR_RESULT_MAP_FAILED;

  jar->file = file;
  jar->st_size = s.st_size;
  jar->parse = (char*)file;
  jar->n = 0;

  if (!cookiejar_parse_do(jar)) /* parse the file */
    return COOKIEJAR_RESULT_INVALID_FILE;

  jar->parse = NULL;

  return COOKIEJAR_RESULT_OK;
}

