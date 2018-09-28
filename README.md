# netscape-cookiejar
A simple program to modify the cookies.txt (Netscape) file created by curl. The file _will_ be modified in-place so back up your cookies if you care about them before using this program.

## building
A very simple Makefile is included

## usage
> netscape-cookiejar \<option\> \<Netscape HTTP cookie file\>

### options
#### \<Set-Cookie HTTP header\>
Sets or replaces a cookie. It loosely follows [RFC 6265 section 4.1](https://tools.ietf.org/html/rfc6265#section-4.1) and supports the `cookie-name=cookie-value`, `Domain`, `Path`, `Max-Age`, `Secure`, and `HttpOnly` directives. It does not support `Expires` because I'm lazy (it will tell you to use `Max-Age`.) It will replace an existing cookie by name, domain, and path. See the [Set-Cookie MDN doc](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) for more.

> \$ netscape-cookiejar 'Set-Cookie foo=bar; Domain=www.example.com; Path=/; Max-Age=1337; Secure' cookies.txt

#### -e, --evict \<Name\> \<Domain\> \<Path\>
Cookies can be deleted with the --evict option. Substitute Name, Domain, or Path with '\*' to match any cookie by that directive.

> \$ netscape-cookiejar --evict foo www.example.com / cookies.txt # delete an exact cookie

> \$ netscape-cookiejar --evict \\\* www.example.com \\\* cookies.txt # delete any cookies for the www.example.com Domain

> \$ netscape-cookiejar -e \\\* \\\* \\\* cookies.txt # delete all your cookies

#### -j, --json
Prints the cookies as a null-terminated JSON array of cookie objects to stdout. The cookie object will have `name`, `value`, `domain`, and `path` strings; an `expires` number (unix time;) and `httponly` and `secure` booleans.

> \$ netscape-cookiejar --json cookies.txt | jq '.'
```
[
  {
    "name": "foo",
    "value": "bar",
    "domain": "www.example.com",
    "path": "/",
    "expires": 1538143943,
    "httponly": false,
    "secure": true
  },
  null
]
```
