# chrome-cookies-secure-promise

Extract encrypted Google Chrome cookies for a url on Mac OS X or Linux

This is a fork of https://github.com/bertrandom/chrome-cookies-secure which is
promise based.

## Installation

```
yarn add chrome-cookies-secure-promise
```

## API

getCookies(url[,format])
---------------------------------

`url` should be a fully qualified url, e.g. `http://www.example.com/path/`

`format` is optional and can be one of the following values:

format | description
------------ | -------------
curl | [Netscape HTTP Cookie File](http://curl.haxx.se/docs/http-cookies.html) contents usable by curl and wget
jar | cookie jar compatible with [request](https://www.npmjs.org/package/request)
set-cookie | Array of Set-Cookie header values
header | `cookie` header string, similar to what a browser would send
object | (default) Object where key is the cookie name and value is the cookie value. These are written in order so it's possible that duplicate cookie names will be overriden by later values

If `format` is not specified, `object` will be used as the format by default.

Cookie order tries to follow [RFC 6265 - Section 5.4, step 2](http://tools.ietf.org/html/rfc6265#section-5.4) as best as possible.

## Examples

basic usage
-----------

```
import chrome from 'chrome-cookies-secure';

chrome.getCookies('http://www.example.com/path/')
  .then(cookies => console.log(cookies));
```

jar used with request
---------------------

```
import request from 'request';
import chrome from 'chrome-cookies-secure';

chrome.getCookies('http://www.example.com/', 'jar')
  .then(jar => request({url: 'http://www.example.com/', jar: jar}))
  .then(body => console.log(body));
```

## Limitations

On OS X, this module requires Keychain Access to read the Google Chrome encryption key. The first time you use it, it will popup this dialog:

![image](https://raw.githubusercontent.com/johnf/chrome-cookies-secure-promise/gh-pages/access.png)

The SQLite database that Google Chrome stores its cookies is only persisted to every 30 seconds or so, so this can explain while you'll see a delay between which cookies your browser has access to and this module.

## License

This software is free to use under the MIT license. See the [LICENSE file][] for license text and copyright information.

[LICENSE file]: https://github.com/johnf/chrome-cookies-secure-promise/blob/master/LICENSE.md
