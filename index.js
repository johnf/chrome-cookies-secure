/*
 * Copyright (c) 2015, Yahoo! Inc.  All rights reserved.
 * Copyright (c) 2017, John Ferlito.  All rights reserved.
 * Copyrights licensed under the MIT License.
 * See the accompanying LICENSE file for terms.
 */

const sqlite3 = require('sqlite3');
const tld = require('tldjs');
const tough = require('tough-cookie');
const request = require('request');
const int = require('int');
const url = require('url');
const crypto = require('crypto');
const keytar = require('keytar');
// const Cookie = tough.Cookie;

let path;
let ITERATIONS;
let dbClosed = false;

if (process.platform === 'darwin') {
  path = `${process.env.HOME}/Library/Application Support/Google/Chrome/Default/Cookies`;
  ITERATIONS = 1003;
} else if (process.platform === 'linux') {
  path = `${process.env.HOME}/.config/google-chrome/Default/Cookies`;
  ITERATIONS = 1;
} else {
  console.error('Only Mac and Linux are supported.');
  process.exit();
}

const KEYLENGTH = 16;
const SALT = 'saltysalt';
let db = new sqlite3.Database(path);

// Decryption based on http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
// Inspired by https://www.npmjs.org/package/chrome-cookies
const decrypt = (key, encryptedDataOrig) => {
  let decoded;
  const iv = new Buffer(new Array(KEYLENGTH + 1).join(' '), 'binary');

  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);

  const encryptedData = encryptedDataOrig.slice(3);

  decoded = decipher.update(encryptedData);

  const final = decipher.final();
  final.copy(decoded, decoded.length - 1);

  const padding = decoded[decoded.length - 1];
  if (padding) {
    decoded = decoded.slice(0, decoded.length - padding);
  }

  decoded = decoded.toString('utf8');

  return decoded;
};

const getDerivedKey = (callback) => {
  let chromePassword;

  if (process.platform === 'darwin') {
    chromePassword = keytar.getPassword('Chrome Safe Storage', 'Chrome');
  } else if (process.platform === 'linux') {
    chromePassword = 'peanuts';
  }

  crypto.pbkdf2(chromePassword, SALT, ITERATIONS, KEYLENGTH, callback);
};

// Chromium stores its timestamps in sqlite on the Mac using the Windows Gregorian epoch
// https://github.com/adobe/chromium/blob/master/base/time_mac.cc#L29
// This converts it to a UNIX timestamp

const convertChromiumTimestampToUnix = timestamp => int(timestamp.toString()).sub('11644473600000000').div(1000000);

const convertRawToNetscapeCookieFileFormat = (cookies, domain) => {
  let out = '';
  const cookieLength = cookies.length;

  cookies.forEach((cookie, index) => {
    out += `${cookie.host_key}\t`;
    out += `${((cookie.host_key === `.${domain}`) ? 'TRUE' : 'FALSE')}\t`;
    out += `${cookie.path}\t`;
    out += `${(cookie.secure ? 'TRUE' : 'FALSE')}\t`;

    if (cookie.has_expires) {
      out += `${convertChromiumTimestampToUnix(cookie.expires_utc).toString()}\t`;
    } else {
      out += '0\t';
    }

    out += `${cookie.name}\t`;
    out += `${cookie.value}\t`;

    if (cookieLength > index + 1) {
      out += '\n';
    }
  });

  return out;
};

const convertRawToHeader = (cookies) => {
  let out = '';
  const cookieLength = cookies.length;

  cookies.forEach((cookie, index) => {
    out += `${cookie.name}=${cookie.value}`;
    if (cookieLength > index + 1) {
      out += '; ';
    }
  });

  return out;
};

const convertRawToJar = (cookies, uri) => {
  const jar = new request.jar(); // eslint-disable-line new-cap

  cookies.forEach((cookie /* , index */) => {
    const jarCookie = request.cookie(`${cookie.name}=${cookie.value}`);
    if (jarCookie) {
      jar.setCookie(jarCookie, uri);
    }
  });

  return jar;
};

const convertRawToSetCookieStrings = (cookies) => {
  const strings = [];

  cookies.forEach((cookie /* , index */) => {
    let out = '';

    const dateExpires = new Date(convertChromiumTimestampToUnix(cookie.expires_utc) * 1000);

    out += `${cookie.name}=${cookie.value}; `;
    out += `expires=${tough.formatDate(dateExpires)}; `;
    out += `Domain=${cookie.host_key}; `;
    out += `Path=${cookie.path}`;

    if (cookie.secure) {
      out += '; Secure';
    }

    if (cookie.httponly) {
      out += '; HttpOnly';
    }

    strings.push(out);
  });

  return strings;
};

const convertRawToObject = (cookies) => {
  const out = {};

  cookies.forEach((cookie /* , index */) => {
    out[cookie.name] = cookie.value;
  });

  return out;
};

/*

   Possible formats:
   curl - Netscape HTTP Cookie File contents usable by curl and wget http://curl.haxx.se/docs/http-cookies.html
   jar - request module compatible jar https://github.com/request/request#requestjar
   set-cookie - Array of set-cookie strings
   header - "cookie" header string
   object - key/value of name/value pairs, overlapping names are overwritten

*/
const getCookies = (uri, format, callback) => {
  if (format instanceof Function) {
    callback = format; // eslint-disable-line no-param-reassign
    format = null; // eslint-disable-line no-param-reassign
  }

  const parsedUrl = url.parse(uri);

  if (!parsedUrl.protocol || !parsedUrl.hostname) {
    return callback(new Error('Could not parse URI, format should be http://www.example.com/path/'));
  }

  if (dbClosed) {
    db = new sqlite3.Database(path);
    dbClosed = false;
  }

  getDerivedKey((err, derivedKey) => {
    if (err) {
      return callback(err);
    }

    db.serialize(() => {
      const cookies = [];

      const domain = tld.getDomain(uri);

      if (!domain) {
        return callback(new Error('Could not parse domain from URI, format should be http://www.example.com/path/'));
      }

      // ORDER BY tries to match sort order specified in
      // RFC 6265 - Section 5.4, step 2
      // http://tools.ietf.org/html/rfc6265#section-5.4
      const sql = `
        SELECT
          host_key, path, secure, expires_utc, name, value, encrypted_value, creation_utc, httponly, has_expires, persistent
        FROM
          cookies
        WHERE
          host_key like '%${domain}'
        ORDER BY
          LENGTH(path) DESC,
          creation_utc ASC
      `;
      db.each(sql, (dbErr, cookie) => {
        let encryptedValue;

        if (dbErr) {
          return callback(dbErr);
        }

        if (cookie.value === '') {
          encryptedValue = cookie.encrypted_value;
          cookie.value = decrypt(derivedKey, encryptedValue); // eslint-disable-line no-param-reassign
          delete cookie.encrypted_value; // eslint-disable-line no-param-reassign
        }

        cookies.push(cookie);

        return null;
      }, () => {
        const host = parsedUrl.hostname;
        const innerPath = parsedUrl.path;
        const isSecure = parsedUrl.protocol.match('https');
        let validCookies = [];
        let output;

        cookies.forEach((cookie) => {
          if (cookie.secure && !isSecure) {
            return;
          }

          if (!tough.domainMatch(host, cookie.host_key, true)) {
            return;
          }

          if (!tough.pathMatch(innerPath, cookie.path)) {
            return;
          }

          validCookies.push(cookie);
        });

        const filteredCookies = [];
        const keys = {};

        validCookies.reverse().forEach((cookie) => {
          if (typeof keys[cookie.name] === 'undefined') {
            filteredCookies.push(cookie);
            keys[cookie.name] = true;
          }
        });

        validCookies = filteredCookies.reverse();

        switch (format) {

          case 'curl':
            output = convertRawToNetscapeCookieFileFormat(validCookies, domain);
            break;

          case 'jar':
            output = convertRawToJar(validCookies, uri);
            break;

          case 'set-cookie':
            output = convertRawToSetCookieStrings(validCookies);
            break;

          case 'header':
            output = convertRawToHeader(validCookies);
            break;

          case 'object':
            /* falls through */
          default:
            output = convertRawToObject(validCookies);
            break;

        }

        db.close((db2Err) => {
          if (!db2Err) {
            dbClosed = true;
          }

          return callback(null, output);
        });
      });

      return null;
    });

    return null;
  });

  return null;
};

module.exports = {
  getCookies,
};
