/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint devel: true, node: true, nomen: true, stupid: true */
'use strict';



// Variables
const util = require('util'),
    _ = require('lodash'),
    storage = require('karmia-storage'),
    utility = require('karmia-utility'),
    kutil = utility();


/**
 * EqDigestAuthStrategyObject
 *
 * @class
 */
class EqDigestAuthStrategyObject {

    /**
     * Constructor
     *
     * @constructs EqDigestAuthStrategyObject
     */
    constructor(options) {
        const self = this;
        self.options = options || {};
        self.options.users = self.options.users || [];
        self.options.users = Array.isArray(self.options.users) ? self.options.users : [self.options.users];
        self.options.storage = self.options.storage || {};

        self.storage = storage.memory({size: options.storage.size || 10000});
        self.users = self.options.users.map(function (value) {
            const username = util.format('%s:%s', value.username, value.realm || options.realm);
            value.md5 = kutil.crypto.hash('md5', username).toString('hex');
            value.sha256 = kutil.crypto.hash('sha256', username).toString('hex');
            value.sha512 = kutil.crypto.hash('sha512/256', username).toString('hex');

            return value;
        });
    }

    /**
     * Generate nonce parameter
     *
     * @returns {Promise}
     */
    nonce() {
        const self = this,
            result = kutil.random.string(32, {special: false});
        self.storage.store(result, null);

        return Promise.resolve(result);
    }

    /**
     * Get user credential
     *
     * @param   {string} username
     * @param   {Boolean} userhash
     * @param   {string} algorithm
     * @returns {Promise}
     */
    credential(username, userhash, algorithm) {
        const self = this;
        username = Buffer.isBuffer(username) ? username.toString('hex') : username;

        if (userhash) {
            if (/^sha[-_]?256$/i.test(algorithm)) {
                return Promise.resolve(self.users.find(function (user) {
                    return (user.sha256 === username);
                }));
            }

            if (/^sha[-_]?512[-_/]256$/i.test(algorithm)) {
                return Promise.resolve(self.users.find(function (user) {
                    return (user.sha512 === username);
                }));
            }

            return Promise.resolve(self.users.find(function (user) {
                return (user.md5 === username);
            }));
        }

        return Promise.resolve(self.users.find(function (user) {
            return (user.username === username);
        }));
    }

    /**
     * Secret callback function
     *
     * @param   {Object} auth
     * @param   {Object} parameters
     * @returns {Promise}
     */
    secret(auth, parameters) {
        const self = this,
            username = parameters.username,
            userhash = _.isString(parameters.userhash) ? parameters.userhash.toLowerCase() : parameters.userhash,
            algorithm = (parameters.algorithm || 'md5').toLowerCase().replace('sha-', 'sha').replace('-sess', '');

        return new Promise(function (resolve, reject) {
            self.credential(username, kutil.string.toBoolean(userhash), algorithm).then(function (result) {
                if (result) {
                    resolve({
                        username: username,
                        password: result.password
                    });
                } else {
                    const error = new Error('Unauthorized');
                    error.code = 401;

                    reject(error);
                }
            });
        });
    }

    /**
     * Secret callback function
     *
     * @param   {Object} auth
     * @param   {Object} parameters
     * @returns {Promise}
     */
    validate(auth, parameters) {
        const self = this,
            nonce = parameters.nonce;

        return new Promise(function (resolve, reject) {
            self.storage.has(nonce).then(function (result) {
                if (result) {
                    return resolve(result);
                }

                const error = new Error('Unauthorized');
                error.code = 401;

                reject(error);
            });
        });
    }
}


// Export module
module.exports = function (options) {
    return new EqDigestAuthStrategyObject(options);
};



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
