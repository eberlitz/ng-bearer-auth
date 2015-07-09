# [ng-bearer-auth](https://github.com/eberlitz/ng-bearer-auth/)

Token-based AngularJS Authentication

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [License](#license)

## Installation

```bash
# Bower
bower install ng-bearer-auth

# NPM
npm install ng-bearer-auth
```

## Usage

`TODO`

```js
angular.module('sampleApp', [
    'ngBearerAuth',
    'ngBearerAuthInterceptor'
])
.config(function ($authProvider){
    // Default configuration
    $authProvider.configure({
        clientId: "AppKey",
        clientSecret: "AppSecret",
        url: "http://localhost:3000/server/api/"
    });

    // Named configuration
    $authProvider.configure({
        name: "api2",
        clientId: "AppKey",
        clientSecret: "AppSecret",
        url: "http://localhost:3000/server2/api/"
    });
})
.controller('sampleCtrl',function($auth, $authService){
    $auth.isAuthenticated();

    $authService.configure({
        name: "api3",
        clientId: "Api3Id"
    });

    var auth = $authService.get("api3");
    console.log(auth.config.clientId);
    auth.isAuthenticated();
});
```

## API Reference

`TODO`

```js
/*
Sign in using resource owner or client credentials

options: {
    username?: string,
    password?: string,
    cliend_id?: string,
    client_secret?: string,
    authorizeUrl?: string,
    persistent?: boolean
}*/
$auth.authorize(options)

// Removes authorization tokens from Storage.
$auth.removeToken()

// Returns true if an refresh token or access token is present in Storage and it is not expired, otherwise returns false.
$auth.isAuthenticated()

// Returns an access token from the Storage if it is not expired. If there is an Refresh Token in Storage exchange it for an access token within the server.
$auth.getToken()

// Saves an authorization token to Storage.
$auth.setToken(token)
```

## Interceptor

`TODO`

```js
$authInterceptor
    request
        find $auth by url match
            $auth._authorizeRequest(requestConfig);

    responseError
        statusCode 401
            find $auth by url match
                $auth.removeToken()
                $auth._authorizeRequest(requestConfig); 
```

## License

The MIT License (MIT)

Copyright (c) 2015 Eduardo Eidelwein Berlitz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

