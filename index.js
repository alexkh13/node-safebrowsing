const redis = require('redis');
const moment = require('moment');
const client = redis.createClient();
const google = require('googleapis');
const safebrowsing = google.safebrowsing('v4');
const Hashes = require('./util/Hashes');
const _ = require('underscore');
const getCanonicalizedURL = require('./util/getCanonicalizedURL');
const getLookupExpressions = require('./util/getLookupExpressions');

module.exports = function(config) {

    const Lists = config.Lists || DefaultLists;

    let updateTimeout;

    function getMinimumWaitDuration() {
        return new Promise((resolve) => {
            client.get("safebrowse:nextupdate", (err, nextUpdate) => {
                if(err) throw err;
                resolve(nextUpdate ? moment(+nextUpdate).diff() : null);
            });
        })
    }

    function update() {
        return new Promise(async (resolve) => {
            let timeout = await getMinimumWaitDuration() || 0;
            timeout > 0 && notifyListeners("update:scheduled", {
                nextUpdate: timeout/1000
            });
            updateTimeout = setTimeout(async () => {
                notifyListeners("update:started");
                let updates = await getThreatListUpdates();
                let minimumWaitDuration = Math.ceil(parseFloat(updates['minimumWaitDuration'])) || 300;
                let nextUpdate = +moment().add(minimumWaitDuration, 'seconds').toDate();
                await handleUpdates(updates);
                notifyListeners("update:complete");
                client.set("safebrowse:nextupdate", nextUpdate, (err) => {
                    if (err) throw err;
                    update();
                    resolve();
                });
            }, timeout);
        });
    }

    function getThreatListUpdates() {
        return new Promise(async (resolve, reject) => {
            safebrowsing.threatListUpdates.fetch({
                auth: config.API_KEY,
                resource: {
                    "client": config.CLIENT,
                    "listUpdateRequests": await getLists()
                }
            }, (err, result) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(result);
                }
            });
        });
    }

    function getFullHashes(request) {

        return new Promise((resolve, reject) => {
            safebrowsing.fullHashes.find({
                auth: config.API_KEY,
                resource: {
                    "client": config.CLIENT,
                    "clientStates": request.clientStates,
                    "threatInfo": {
                        "threatTypes":      request.threatTypes,
                        "platformTypes":    request.platformTypes,
                        "threatEntryTypes": request.threatEntryTypes,
                        "threatEntries": request.prefixes.map((hash) => ({
                            "hash": hash
                        }))
                    }
                }
            }, (err, result) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(result);
                }
            });
        });
    }

    function getLists() {
        return Promise.all(_.map(Lists, async (list) => {
            return _.extend({}, list, {
                state: await getListState(getListCode(list))
            });
        }));
    }

    async function check(url) {

        let canonicalized = getCanonicalizedURL(url);
        let exprs = _.uniq(getLookupExpressions(canonicalized));
        let prefixes = exprs.map((expr) => Hashes.getHashObject(expr));

        let partialMatches = [];

        let lists = await getPrefixesLists();

        for(let prefix of prefixes) {
            for(let list of lists) {
                if (await prefixExists(list, prefix.prefix.toString('base64'))) {
                    let code = list.split(":")[1];
                    partialMatches.push(_.extend({}, ListCodes[code], prefix, {
                        clientState: await getListState(code)
                    }));
                }
            }
        }

        let fullMatches = [];

        if (partialMatches.length) {

            let cached = await Promise.all(_.map(partialMatches, (partialMatch) => {
                return getCachedMatch(partialMatch);
            }));

            fullMatches = fullMatches.concat(_.compact(cached));

            partialMatches = _.filter(partialMatches, (match, index) => {
                return !cached[index];
            });

            if (partialMatches.length) {

                let prefixes = _.chain(partialMatches).map((m)=>m.prefix.toString('base64')).value();
                let threatTypes = _.chain(partialMatches).pluck("threatType").uniq().value();
                let platformTypes = _.chain(partialMatches).pluck("platformType").uniq().value();
                let threatEntryTypes = _.chain(partialMatches).pluck("threatEntryType").uniq().value();
                let clientStates = _.chain(partialMatches).pluck("clientState").uniq().value();

                let {matches} = await getFullHashes({
                    prefixes,
                    threatTypes,
                    platformTypes,
                    threatEntryTypes,
                    clientStates
                });

                let fullHashes = _.chain(partialMatches).map((m)=>m.hash.toString('base64')).value();

                for(let match of matches) {
                    if (fullHashes.includes(match.threat.hash)) {
                        fullMatches.push(match);
                        await cacheMatch(match);
                    }
                }
            }

        }

        return fullMatches;

    }

    function notifyListeners(eventType, ...args) {
        _.each(listeners[eventType], (cb) => cb.apply(this, args));
    }

    let initPromise;
    let listeners = {};

    return {
        start: () => {
            initPromise = update();
        },
        check: async (url) => {
            await initPromise;
            let wait = await getMinimumWaitDuration();
            if (wait === null) {
                throw new Error("db not initialized");
            }
            return check(url);
        },
        stop: () => {
            clearTimeout(updateTimeout);
            client.quit();
        },
        on: (eventType, cb) => {
            if (!listeners[eventType]) listeners[eventType] = [];
            listeners[eventType].push(cb);
        }
    }
};

const DefaultLists = [
    {
        "threatType": "MALWARE",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL"
    },
    {
        "threatType": "SOCIAL_ENGINEERING",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL"
    },
    {
        "threatType": "POTENTIALLY_HARMFUL_APPLICATION",
        "platformType": "ANDROID",
        "threatEntryType": "URL"
    },
    {
        "threatType": "POTENTIALLY_HARMFUL_APPLICATION",
        "platformType": "IOS",
        "threatEntryType": "URL"
    },
    {
        "threatType": "UNWANTED_SOFTWARE",
        "platformType": "ANY_PLATFORM",
        "threatEntryType": "URL"
    }
];

const ThreatTypes = {
    'MALWARE': 1,
    'SOCIAL_ENGINEERING': 2,
    'POTENTIALLY_HARMFUL_APPLICATION': 3,
    'UNWANTED_SOFTWARE': 4
};

const PlatformTypes = {
    'ANY_PLATFORM': 1,
    'WINDOWS': 2,
    'LINUX': 3,
    'OSX': 4,
    'ALL_PLATFORMS': 5,
    'CHROME': 6,
    'ANDROID': 7,
    'IOS': 8
};

const ThreatEntryTypes = {
    'URL': 1,
    'IP_RANGE': 2
};

const ListCodes = {};

_.each(ThreatTypes, (n1, threatType) => {
    _.each(PlatformTypes, (n2, platformType) => {
        _.each(ThreatEntryTypes, (n3, threatEntryType) => {
            let code = [n1,n2,n3].join('');
            ListCodes[code] = {
                threatType,
                threatEntryType,
                platformType
            };
        })
    })
});

function getListCode(list) {
    return [
        ThreatTypes[list.threatType],
        PlatformTypes[list.platformType],
        ThreatEntryTypes[list.threatEntryType]
    ].join('');
}

function getListKey(threatType, platformType, threatEntryType) {
    return "safebrowse:" + getListCode({threatType, platformType, threatEntryType});
}

function getListItem(list, index) {
    return new Promise((resolve) => {
        client.lindex(list, index, (err, item) => {
            if (err) throw err;
            resolve(item);
        })
    })
}

async function handleUpdates(updates) {

    for(let listUpdateResponse of updates['listUpdateResponses']) {

        let batch = client.batch();

        let key = getListKey(
            listUpdateResponse.threatType,
            listUpdateResponse.platformType,
            listUpdateResponse.threatEntryType);

        let prefixesSetKey = key + ":prefixes:set";
        let prefixesListKey = key + ":prefixes:list";

        if (listUpdateResponse.responseType === 'FULL_UPDATE') {
            batch.del(prefixesSetKey);
            batch.del(prefixesListKey);
        }

        batch.set(key + ":state", listUpdateResponse.newClientState);

        await Promise.all(_.map(listUpdateResponse.removals, async (removal) => {
            let {indices} = removal.rawIndices;
            indices = indices.reverse();
            await Promise.all(_.map(indices, async (index) => {
                batch.lset(prefixesListKey, index, 'DELETED');
                batch.lrem(prefixesListKey, 1, 'DELETED');
                let prefix = await getListItem(prefixesListKey, index);
                batch.srem(prefixesSetKey, prefix);
            }));
        }));

        _.each(listUpdateResponse.additions, (addition) => {
            let {rawHashes,prefixSize} = addition.rawHashes;
            let buff = Buffer.from(rawHashes, 'base64');
            for(let i=0;i<buff.length; i+=prefixSize) {
                let prefix = buff.slice(i, i+prefixSize).toString('base64');
                batch.sadd(prefixesSetKey, prefix);
                batch.lpush(prefixesListKey, prefix);
            }
        });

        await new Promise((resolve) => {
            batch.exec((err) => {
                if (err) throw err;
                resolve();
            });
        })
    }
}

function getPrefixesLists() {
    return new Promise((resolve) => {
        return client.keys("safebrowse:*:prefixes:set", (err, lists) => {
            if (err) throw err;
            resolve(lists);
        });
    });
}

function getListState(code) {
    return new Promise((resolve) => {
        return client.get("safebrowse:" + code + ":state", (err, state) => {
            if (err) throw err;
            resolve(state);
        });
    });
}

function prefixExists(list, prefix) {
    return new Promise((resolve) => {
        client.sismember(list, prefix, (err, reply) => {
            if (err) throw err;
            resolve(!!reply);
        });
    })
}

function cacheMatch(match) {
    let list = getListKey(match.threatType, match.platformType, match.threatEntryType);
    let hash = match.threat.hash;
    let timeout = parseInt(match.cacheDuration);
    let key = list + ":hash:" + hash;
    return new Promise((resolve) => {
        client.set(key, JSON.stringify(match), (err) => {
            if (err) throw err;
            client.expire(key, timeout, (err) => {
                if (err) throw err;
                resolve();
            });
        });
    })
}

function getCachedMatch(partialMatch) {
    let list = getListKey(partialMatch.threatType, partialMatch.platformType, partialMatch.threatEntryType);
    let hash = partialMatch.hash.toString('base64');
    return new Promise((resolve) => {
        client.get(list + ":hash:" + hash, (err, reply) => {
            if (err) throw err;
            resolve(JSON.parse(reply));
        });
    })
}