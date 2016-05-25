# eq-digest-authentication-strategy
Strategy module for [Eq digest authentication](https://github.com/eq-inc/eq-digest-authentication)

## Example

```JavaScript
const digest_authentication = require('eq-digest-authentication'),
    digest_authentication_strategy = require('eq-digest-authentication-strategy'),
    users = [
        {username: 'username1', password: 'password1'},
        {username: 'username2', password: 'password2'}
    ],
    options = {
        realm: 'realm',
        qop: 'auth',
        algorithm: 'sha-256'
    },
    strategy = digest_authentication_strategy.object(users, options),
    digest_authentication = digest_authentication(strategy, options);
```
