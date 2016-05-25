# eq-digest-authentication-strategy
Strategy module for [Eq digest authentication](https://github.com/eq-inc/eq-digest-authentication)

## Example

```JavaScript
const digest_authentication = require('eq-digest-authentication'),
    digest_authentication_strategy = require('eq-digest-authentication-strategy'),
    type = 'object',
    options = {
        realm: 'realm',
        algorithm: 'sha-256',
        qop: 'auth',
        users: [
            {username: 'username1', password: 'password1'},
            {username: 'username2', password: 'password2'}
        ]
    },
    strategy = digest_authentication_strategy(type, options),
    digest_authentication = digest_authentication(strategy, options);
```
