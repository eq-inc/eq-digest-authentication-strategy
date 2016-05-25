/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint devel: true, node: true, nomen: true, stupid: true */
/*global before, describe, it */
'use strict';



// Variables
let strategy;
const util = require('util'),
    co = require('co'),
    expect = require('expect.js'),
    utility = require('karmia-utility'),
    authentication_strategy = require('../'),
    options = {
        type: 'object',
        algorithm: 'sha-256',
        realm: 'eq-digest-auth-strategy-object',
        qop: 'auth',
        users: {
            username: 'test_username',
            password: 'test_password'
        }
    };


// Before
before(function () {
    strategy = authentication_strategy(options);
});


// Test
describe('Test', function () {
    describe('nonce', function () {
        it('Should get nonce', function (done) {
            co(function* () {
                const nonce = yield strategy.nonce();

                expect(nonce).to.have.length(32);
                expect(yield strategy.storage.has(nonce)).to.be(true);

                done();
            });
        });
    });

    describe('credential', function () {
        describe('Should get credential data', function () {
            it('Raw', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        credential = yield strategy.credential(user.username, false);

                    expect(Object.keys(credential).sort()).to.eql(['md5', 'password', 'sha256', 'sha512', 'username']);
                    expect(credential.username).to.be(user.username);
                    expect(credential.password).to.be(user.password);
                    ['md5', 'sha256', 'sha512/256'].forEach(function (algorithm) {
                        const key = ('sha512/256' === algorithm) ? 'sha512' : algorithm;
                        expect(credential[key]).to.be(utility.crypto.hash(algorithm, username).toString('hex'));
                    });

                    done();
                });
            });

            it('MD5', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        md5 = utility.crypto.hash('md5', username).toString('hex'),
                        credential = yield strategy.credential(md5, true, 'md5');

                    expect(Object.keys(credential).sort()).to.eql(['md5', 'password', 'sha256', 'sha512', 'username']);
                    expect(credential.username).to.be(user.username);
                    expect(credential.password).to.be(user.password);
                    ['md5', 'sha256', 'sha512/256'].forEach(function (algorithm) {
                        const key = ('sha512/256' === algorithm) ? 'sha512' : algorithm;
                        expect(credential[key]).to.be(utility.crypto.hash(algorithm, username).toString('hex'));
                    });

                    done();
                }).catch(function (error) {
                    console.log(error);
                    done();
                });
            });

            it('SHA256', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        sha256 = utility.crypto.hash('sha256', username),
                        credential = yield strategy.credential(sha256, true, 'sha256');

                    expect(Object.keys(credential).sort()).to.eql(['md5', 'password', 'sha256', 'sha512', 'username']);
                    expect(credential.username).to.be(user.username);
                    expect(credential.password).to.be(user.password);
                    ['md5', 'sha256', 'sha512/256'].forEach(function (algorithm) {
                        const key = ('sha512/256' === algorithm) ? 'sha512' : algorithm;
                        expect(credential[key]).to.be(utility.crypto.hash(algorithm, username).toString('hex'));
                    });

                    done();
                });
            });

            it('SHA512/256', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        sha512_256 = utility.crypto.hash('sha512/256', username),
                        credential = yield strategy.credential(sha512_256, true, 'sha512/256');

                    expect(Object.keys(credential).sort()).to.eql(['md5', 'password', 'sha256', 'sha512', 'username']);
                    expect(credential.username).to.be(user.username);
                    expect(credential.password).to.be(user.password);
                    ['md5', 'sha256', 'sha512/256'].forEach(function (algorithm) {
                        const key = ('sha512/256' === algorithm) ? 'sha512' : algorithm;
                        expect(credential[key]).to.be(utility.crypto.hash(algorithm, username).toString('hex'));
                    });

                    done();
                });
            });

            it('No algorithm specified', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        md5 = utility.crypto.hash('md5', username),
                        credential = yield strategy.credential(md5, true);

                    expect(Object.keys(credential).sort()).to.eql(['md5', 'password', 'sha256', 'sha512', 'username']);
                    expect(credential.username).to.be(user.username);
                    expect(credential.password).to.be(user.password);
                    ['md5', 'sha256', 'sha512/256'].forEach(function (algorithm) {
                        const key = ('sha512/256' === algorithm) ? 'sha512' : algorithm;
                        expect(credential[key]).to.be(utility.crypto.hash(algorithm, username).toString('hex'));
                    });

                    done();
                });
            });
        });
    });

    describe('secret', function () {
        describe('Should get secret data', function () {
            it('Raw', function (done) {
                co(function* () {
                    const user = options.users[0],
                        parameters = {
                            username: user.username,
                            userhash: false
                        },
                        secret = yield strategy.secret(null, parameters);

                    expect(secret).to.eql({
                        username: user.username,
                        password: user.password
                    });

                    done();
                });
            });

            it('MD5', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        parameters = {
                            username: utility.crypto.hash('md5', username).toString('hex'),
                            userhash: true,
                            algorithm: 'md5'
                        },
                        secret = yield strategy.secret(null, parameters);

                    expect(secret).to.eql({
                        username: parameters.username,
                        password: user.password
                    });


                    done();
                });
            });

            it('SHA256', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        parameters = {
                            username: utility.crypto.hash('sha256', username).toString('hex'),
                            userhash: 'true',
                            algorithm: 'sha-256'
                        },
                        secret = yield strategy.secret(null, parameters);

                    expect(secret).to.eql({
                        username: parameters.username,
                        password: user.password
                    });


                    done();
                });
            });

            it('SHA512/256', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        parameters = {
                            username: utility.crypto.hash('sha512/256', username).toString('hex'),
                            userhash: 'true',
                            algorithm: 'sha-512-256'
                        },
                        secret = yield strategy.secret(null, parameters);

                    expect(secret).to.eql({
                        username: parameters.username,
                        password: user.password
                    });


                    done();
                });
            });

            it('No algorithm specified', function (done) {
                co(function* () {
                    const user = options.users[0],
                        username = util.format('%s:%s', user.username, options.realm),
                        parameters = {
                            username: utility.crypto.hash('md5', username).toString('hex'),
                            userhash: 'true'
                        },
                        secret = yield strategy.secret(null, parameters);

                    expect(secret).to.eql({
                        username: parameters.username,
                        password: user.password
                    });


                    done();
                });
            });
        });
    });

    describe('validate', function () {
        it('Should validation success', function (done) {
            co(function* () {
                const nonce = yield strategy.nonce();
                strategy.validate(null, {nonce: nonce}).then(function () {
                    done();
                });
            });
        });

        it('Should be error', function (done) {
            co(function* () {
                strategy.validate(null, {nonce: 'NONCE_NOT_FOUND'}).catch(function (error) {
                    expect(error.code).to.be(401);
                    expect(error.message).to.be('Unauthorized');

                    done();
                });
            });
        });
    });
});



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
