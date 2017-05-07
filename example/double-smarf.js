const chrome = require('../src/index');

chrome.getCookies('http://smarf.toomanycooks.kitchen', (/* err, cookies */) => {
  chrome.getCookies('http://smarf.toomanycooks.kitchen', (err, cookies) => {
    if (err) {
      console.error(err);
      return;
    }

    console.log(cookies); // eslint-disable-line no-console
  });
});
