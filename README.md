# node-safebrowsing
Node client for Google's Safe Browsing Update API v4.

# Usage
```
const safeBrowsing = require('node-safebrowsing')({
  API_KEY: "YOUR_API_KEY_HERE",
  CLIENT: { 
    clientId: "YOUR_CLIENT_ID_HERE",
    clientVersion: "YOU_CLIENT_VERSION_HERE"
  },
  // [optional] array of objects representing the lists to be checked 
  // checkout google's safebrowsing api
  // leave empty for some predefined defaults
  Lists: [{
    "threatType": "MALWARE",
    "platformType": "ANY_PLATFORM",
    "threatEntryType": "URL"
  }]
});

safeBrowsing.check("http://google.com").then((results) => {
  if (results.length) {
    // url appears in one or more lists 
  }
  else {
    // url is clean
  }
});

safeBrowsing.stop(); // quit redis and stop update timeout cycle
```
