/*
 * Copyright (c) 2015, Yahoo! Inc.  All rights reserved.
 * Copyright (c) 2017, John Ferlito.  All rights reserved.
 * Copyrights licensed under the MIT License.
 * See the accompanying LICENSE file for terms.
 */

import db from 'sqlite'; // eslint-disable-line import/extensions
import tld from 'tldjs';
import tough from 'tough-cookie';
import request from 'request';
import url from 'url';
import crypto from 'crypto';
import keytar from 'keytar';
import { spawn } from 'child_process';

const config = {
  keyLength: 16,
};

if (process.platform === 'darwin') {
  config.path = `${process.env.HOME}/Library/Application Support/Google/Chrome/Default/Cookies`;
  config.iterations = 1003;
} else if (process.platform === 'linux') {
  config.path = `${process.env.HOME}/.config/google-chrome/Default/Cookies`;
  config.iterations = 1;
} else {
  throw new Error('Only OS X and Linux are supported.');
}

// Decryption based on http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
// Inspired by https://www.npmjs.org/package/chrome-cookies
const decrypt = (key, encryptedDataOrig) => {
  let decoded;
  const iv = new Buffer(new Array(config.keyLength + 1).join(' '), 'binary');

  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);

  const encryptedData = encryptedDataOrig.slice(3);

  decoded = decipher.update(encryptedData);

  const final = decipher.final();

  decoded = Buffer.concat([decoded, final]);

  const padding = decoded[decoded.length - 1];
  if (padding) {
    decoded = decoded.slice(0, decoded.length - padding);
  }

  decoded = decoded.toString('utf8');

  return decoded;
};

const getOSXSecret = () => keytar.getPassword('Chrome Safe Storage', 'Chrome');

const getLinuxSecret = () => new Promise((resolve /* , reject */) => {
  const secret = spawn('secret-tool', ['lookup', 'application', 'chrome']);

  secret.stdout.on('data', data => resolve(data));

  secret.on('close', (code) => {
    if (code !== 0) {
      resolve('peanuts');
    }
  });

  secret.on('error', (err) => {
    if (err.code === 'ENOENT') {
      throw new Error('You must install secret-tool');
    }

    throw err;
  });
});

const getDerivedKey = () => {
  let secretFunction;

  if (process.platform === 'darwin') {
    secretFunction = getOSXSecret;
  } else if (process.platform === 'linux') {
    secretFunction = getLinuxSecret;
  }

  return secretFunction()
    .then((chromePassword) => {
      const salt = 'saltysalt';
      const digest = 'SHA1';

      return new Promise((resolve, reject) => {
        crypto.pbkdf2(chromePassword, salt, config.iterations, config.keyLength, digest, (err, derivedKey) => {
          if (err) {
            reject(err);
          }

          resolve(derivedKey);
        });
      });
    });
};

// Chromium stores its timestamps in sqlite on the Mac using the Windows Gregorian epoch
// https://github.com/adobe/chromium/blob/master/base/time_mac.cc#L29
// This converts it to a UNIX timestamp
const convertChromiumTimestampToUnix = timestamp => (timestamp - 11644473600000000) / 1000000;

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

  cookies.forEach((cookie) => {
    const jarCookie = request.cookie(`${cookie.name}=${cookie.value}`);
    if (jarCookie) {
      jar.setCookie(jarCookie, uri);
    }
  });

  return jar;
};

const convertRawToSetCookieStrings = (cookies) => {
  const strings = [];

  cookies.forEach((cookie) => {
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

  cookies.forEach((cookie) => {
    out[cookie.name] = cookie.value;
  });

  return out;
};

const getDBRows = (domain) => {
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

  return db.open(config.path)
    .then(() => db.all(sql))
    .then((rows) => {
      db.close();
      return rows;
    });
};

/*
  Possible formats:
    curl - Netscape HTTP Cookie File contents usable by curl and wget http://curl.haxx.se/docs/http-cookies.html
    jar - request module compatible jar https://github.com/request/request#requestjar
    set-cookie - Array of set-cookie strings
    header - "cookie" header string
    object - key/value of name/value pairs, overlapping names are overwritten
*/
export const getCookies = async (uri, format) => {
  const parsedUrl = url.parse(uri);

  if (!parsedUrl.protocol || !parsedUrl.hostname) {
    throw new Error('Could not parse URI, format should be http://www.example.com/path/');
  }

  const domain = tld.getDomain(uri);
  if (!domain) {
    throw new Error('Could not parse domain from URI, format should be http://www.example.com/path/');
  }

  const derivedKey = await getDerivedKey();
  const rows = await getDBRows(domain);

  const host = parsedUrl.hostname;
  const innerPath = parsedUrl.path;
  const isSecure = parsedUrl.protocol.match('https');

  const allCookies = [];
  rows.forEach((cookie) => {
    if (cookie.value !== '' || cookie.encrypted_value.length === 0) {
      return;
    }

    cookie.value = decrypt(derivedKey, cookie.encrypted_value); // eslint-disable-line no-param-reassign

    if (cookie.secure && !isSecure) {
      return;
    }

    if (!tough.domainMatch(host, cookie.host_key, true)) {
      return;
    }

    if (!tough.pathMatch(innerPath, cookie.path)) {
      return;
    }

    allCookies.push(cookie);
  });

  // Keep only most specific cookies
  const filteredCookies = [];
  const keys = {};

  allCookies.reverse().forEach((cookie) => {
    if (typeof keys[cookie.name] === 'undefined') {
      filteredCookies.push(cookie);
      keys[cookie.name] = true;
    }
  });

  const validCookies = filteredCookies.reverse();

  let output;

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

  return output;
};

export default { getCookies };
