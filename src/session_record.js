const BaseKeyType = require('./base_key_type');

const CLOSED_SESSIONS_MAX = 15;
const SESSION_RECORD_VERSION = 'v1';

function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError('Buffer required');
    }
}

class SessionEntry {

    constructor() {
        this._chains = {};
    }

    toString() {
        const baseKey = this.indexInfo && this.indexInfo.baseKey &&
            this.indexInfo.baseKey.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
    }

    inspect() {
        return this.toString();
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return this.toString();
    }

    addChain(key, value) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (this._chains.hasOwnProperty(id)) {
            throw new Error('Overwrite attempt');
        }
        this._chains[id] = value;
    }

    getChain(key) {
        assertBuffer(key);
        return this._chains[key.toString('base64')];
    }

    deleteChain(key) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (!this._chains.hasOwnProperty(id)) {
            throw new ReferenceError('Not Found');
        }
        delete this._chains[id];
    }

    *chains() {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    serialize() {
        const ratchet = this.currentRatchet;
        const info = this.indexInfo;
        const data = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: ratchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: ratchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: ratchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: ratchet.previousCounter,
                rootKey: ratchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: info.baseKey.toString('base64'),
                baseKeyType: info.baseKeyType,
                closed: info.closed,
                used: info.used,
                created: info.created,
                remoteIdentityKey: info.remoteIdentityKey.toString('base64')
            },
            _chains: this._serialize_chains(this._chains)
        };
        if (this.pendingPreKey) {
            data.pendingPreKey = Object.assign({}, this.pendingPreKey);
            data.pendingPreKey.baseKey = this.pendingPreKey.baseKey.toString('base64');
        }
        return data;
    }

    static deserialize(data) {
        const obj = new this();
        const ratchet = data.currentRatchet;
        const info = data.indexInfo;
        obj.registrationId = data.registrationId;
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: Buffer.from(ratchet.ephemeralKeyPair.pubKey, 'base64'),
                privKey: Buffer.from(ratchet.ephemeralKeyPair.privKey, 'base64')
            },
            lastRemoteEphemeralKey: Buffer.from(ratchet.lastRemoteEphemeralKey, 'base64'),
            previousCounter: ratchet.previousCounter,
            rootKey: Buffer.from(ratchet.rootKey, 'base64')
        };
        obj.indexInfo = {
            baseKey: Buffer.from(info.baseKey, 'base64'),
            baseKeyType: info.baseKeyType,
            closed: info.closed,
            used: info.used,
            created: info.created,
            remoteIdentityKey: Buffer.from(info.remoteIdentityKey, 'base64')
        };
        obj._chains = this._deserialize_chains(data._chains);
        if (data.pendingPreKey) {
            obj.pendingPreKey = Object.assign({}, data.pendingPreKey);
            obj.pendingPreKey.baseKey = Buffer.from(data.pendingPreKey.baseKey, 'base64');
        }
        return obj;
    }

    _serialize_chains(chains) {
        const result = {};
        for (const chainId of Object.keys(chains)) {
            const chain = chains[chainId];
            const messageKeys = {};
            for (const [idx, messageKey] of Object.entries(chain.messageKeys)) {
                messageKeys[idx] = messageKey.toString('base64');
            }
            result[chainId] = {
                chainKey: {
                    counter: chain.chainKey.counter,
                    key: chain.chainKey.key && chain.chainKey.key.toString('base64')
                },
                chainType: chain.chainType,
                messageKeys
            };
        }
        return result;
    }

    static _deserialize_chains(chainsData) {
        const result = {};
        for (const chainId of Object.keys(chainsData)) {
            const chain = chainsData[chainId];
            const messageKeys = {};
            for (const [idx, messageKey] of Object.entries(chain.messageKeys)) {
                messageKeys[idx] = Buffer.from(messageKey, 'base64');
            }
            result[chainId] = {
                chainKey: {
                    counter: chain.chainKey.counter,
                    key: chain.chainKey.key && Buffer.from(chain.chainKey.key, 'base64')
                },
                chainType: chain.chainType,
                messageKeys
            };
        }
        return result;
    }
}

const migrations = [{
    version: 'v1',
    migrate: function migrateV1(data) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const key in sessions) {
                if (!sessions[key].registrationId) {
                    sessions[key].registrationId = data.registrationId;
                }
            }
        } else {
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed === -1) {
                    console.error('V1 session storage migration error: registrationId',
                                  data.registrationId, 'for open session version',
                                  data.version);
                }
            }
        }
    }
}];

class SessionRecord {

    static createEntry() {
        return new SessionEntry();
    }

    static migrate(data) {
        let run = (data.version === undefined);
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                migrations[i].migrate(data);
            } else if (migrations[i].version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error('Error migrating SessionRecord');
        }
    }

    static deserialize(data) {
        if (data.version !== SESSION_RECORD_VERSION) {
            this.migrate(data);
        }
        const obj = new this();
        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                obj.sessions[key] = SessionEntry.deserialize(entry);
            }
        }
        return obj;
    }

    constructor() {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
    }

    serialize() {
        const _sessions = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            _sessions[key] = entry.serialize();
        }
        return {
            _sessions,
            version: this.version
        };
    }

    haveOpenSession() {
        const openSession = this.getOpenSession();
        return (!!openSession && typeof openSession.registrationId === 'number');
    }

    getSession(key) {
        assertBuffer(key);
        const session = this.sessions[key.toString('base64')];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error('Tried to lookup a session using our basekey');
        }
        return session;
    }

    getOpenSession() {
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                return session;
            }
        }
    }

    setSession(session) {
        this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
    }

    getSessions() {
        return Object.values(this.sessions).sort((a, b) =>
            (b.indexInfo.used || 0) - (a.indexInfo.used || 0));
    }

    closeSession(session) {
        if (this.isClosed(session)) {
            return;
        }
        session.indexInfo.closed = Date.now();
    }

    openSession(session) {
        session.indexInfo.closed = -1;
    }

    isClosed(session) {
        return session.indexInfo.closed !== -1;
    }

    removeOldSessions() {
        let count = Object.keys(this.sessions).length;
        while (count > CLOSED_SESSIONS_MAX) {
            let oldestKey;
            let oldestSession;
            for (const [key, session] of Object.entries(this.sessions)) {
                if (session.indexInfo.closed !== -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
                    oldestKey = key;
                    oldestSession = session;
                }
            }
            if (oldestKey) {
                delete this.sessions[oldestKey];
                count--;
            } else {
                throw new Error('Corrupt sessions object');
            }
        }
    }

    deleteAllSessions() {
        for (const key of Object.keys(this.sessions)) {
            delete this.sessions[key];
        }
    }
}

module.exports = SessionRecord;
