(function(root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory;
    } else if (typeof angular === 'object' && angular.module) {
        angular.module('ngBearerAuth.service', [])
            .factory('$$storage', function($window) {
                var storage = {

                    getItem: function(name) {
                        return $window.sessionStorage.getItem(name) || $window.localStorage.getItem(name);
                    },
                    removeItem: function(name, isPersistent) {
                        var storage = isPersistent ? $window.localStorage : $window.sessionStorage;
                        return storage.removeItem(name);
                    },
                    setItem: function(name, value, isPersistent) {
                        var storage = isPersistent ? $window.localStorage : $window.sessionStorage;
                        return storage.setItem(name, value);
                    }
                };
                return storage;
            })
            .factory('$$authService', ['$q', '$http', '$$storage', function($q, $http, $storage) {
                return factory($q, $http, $storage);
            }]);
    } else {
        throw new Error('Environment not supported!');
    }
}(this, function($q, $http, $storage) {
    function AuthService(options) {
        var me = this;
        me.options = options;
    }
    AuthService.prototype.authorize = authorize;
    AuthService.prototype.removeToken = removeToken;
    AuthService.prototype.isAuthenticated = isAuthenticated;
    AuthService.prototype.getToken = getToken;
    AuthService.prototype.setToken = setToken;
    AuthService.prototype.getRefreshToken = getRefreshToken;
    AuthService.prototype._authorizeRequest = _authorizeRequest;
    AuthService.prototype._hasRefreshToken = _hasRefreshToken;
    AuthService.prototype._hasAccessToken = _hasAccessToken;
    AuthService.prototype._getData = _getData;
    AuthService.prototype._requestAccessToken = _requestAccessToken;
    AuthService.prototype._addPendingRequest = _addPendingRequest;
    AuthService.prototype._hasPendingRequests = _hasPendingRequests;
    AuthService.prototype._resolveAllPendingRequest = _resolveAllPendingRequest;
    return AuthService;
    // ----------------------------------------------------------
    //
    // Sign in using resource owner or client credentials
    // options: {
    //     username?: string,
    //     password?: string,
    //     cliendId?: string,
    //     clientSecret?: string,
    //     authorizeUrl?: string,
    //     persistent?: boolean
    // }
    function authorize(options, config) {
        //console.log(this.options.name, 'authorize', this.options);
        var me = this;
        var options = extend({
            authorizeUrl: me.options.url + 'token'
        }, me.options, options);
        var deferred = $q.defer();

        var data = {
            grant_type: options.username ? 'password' : 'client_credentials',
            username: options.username,
            password: options.password,
            // Opcionais
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        var body = [];
        for (var prop in data) {
            if (data[prop] != null) {
                body.push(prop + "=" + data[prop]);
            };
        };

        config = extend({
            ignoreAuthInterceptor: true
        }, config);

        $http.post(options.authorizeUrl, body.join("&"), config)
            .then(function(response) {
                me.setToken(response.data, !!options.persistent);
                deferred.resolve(response.data);
            }, function(response) {
                deferred.reject(response.data);
            });

        return deferred.promise;
    }

    // Removes authorization tokens from Storage.
    function removeToken() {
        var me = this;
        //var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;

        var propsToRemove = ["access_token", "refresh_token", "expires_at"];
        propsToRemove.map(function(prop) {
            $storage.removeItem(me.options.name + '-' + prop, me.isPersistent);
        });
    };

    // Returns true if an refresh token or access token is present in Storage and it is not expired, otherwise returns false.
    function isAuthenticated() {
        return this._hasRefreshToken() || this._hasAccessToken();
    };

    function _hasRefreshToken() {
        this.refresh_token = this._getData("refresh_token");
        return !!this.refresh_token;
    }

    function getRefreshToken() {
        if (this._hasRefreshToken()) {
            return this.refresh_token;
        };
        return null;
    };

    function _hasAccessToken() {
        var me = this;
        var now = new Date().getTime();
        var expires_at = me._getData("expires_at");
        if (now < expires_at) {
            me.access_token = me._getData("access_token");
        } else {
            me.access_token = undefined;
        }
        return !!me.access_token;
    }

    function _getData(propName) {
        var me = this;
        propName = me.options.name + '-' + propName;
        return $storage.getItem(propName); // $window.sessionStorage.getItem(propName) || $window.localStorage.getItem(propName);
    }

    // Returns an access token from the Storage if it is not expired. If there is an Refresh Token in Storage exchange it for an access token within the server.
    function getToken() {
        var me = this;
        var deferred = $q.defer();


        function isBadRefreshToken(response) {
            return response[1] === 400 && response[0].error === "invalid_grant";
        }

        if (me._hasAccessToken()) {
            //console.log("hasAccessToken");
            deferred.resolve(this.access_token);
        } else if (me._hasRefreshToken()) {
            //console.log("hasRefreshToken");
            me._requestAccessToken()
                .then(function() {
                    //console.log("RefreshToken exchanged: " + me.refresh_token);
                    deferred.resolve(me.access_token);
                }, function(response) {
                    //console.log("Exchange refreshToken error");
                    if (isBadRefreshToken(response)) {
                        //console.log("isBadRefreshToken");
                        me.removeToken();
                        //console.log("Credentials requested: " + me.options.url);
                        //requestCredentials();
                    } //else abortRequest();
                    deferred.reject(response);
                });
        } else {
            //console.log("Credentials requested: " + me.options.url);
            //requestCredentials();
            deferred.reject("REQUEST_CREDENTIALS");
        }

        return deferred.promise;
    };
    // Saves an authorization token to Storage.
    // tokenData: {
    //  access_token: string,
    //  refresh_token?: string,
    //  expires_in: number,
    // }
    function setToken(tokenData, isPersistent) {
        var me = this;
        if (typeof me.isPersistent !== "undefined" && me.isPersistent !== !!isPersistent) {
            me.removeToken();
        }
        me.isPersistent = !!isPersistent;
        //var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;



        //Calculate exactly when the token will expire, then subtract
        //30sec to give ourselves a small buffer.
        var now = new Date().getTime();
        var expiresAt = now + parseInt(tokenData.expires_in, 10) * 1000 - 30000;

        var toStore = {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token || me._getData("refresh_token"),
            expires_at: expiresAt
        };
        for (var prop in toStore) {
            $storage.setItem(me.options.name + '-' + prop, toStore[prop], me.isPersistent);
        }
        me.access_token = toStore.access_token;
        me.refresh_token = toStore.refresh_token;
    };

    function _requestAccessToken() {
        var me = this;
        var deferred = $q.defer();
        var options = extend({
            authorizeUrl: me.options.url + 'token'
        }, me.options);

        var data = {
            grant_type: 'refresh_token',
            refresh_token: me.refresh_token,
            // Opcionais
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        var body = [];
        for (var prop in data) {
            if (data[prop] != null) {
                body.push(prop + "=" + data[prop]);
            };
        };

        var refreshUrl = options.authorizeUrl;
        if (!me._hasPendingRequests()) {
            me._addPendingRequest(deferred);
            $http.post(refreshUrl, body.join("&"), {
                    ignoreAuthInterceptor: true
                })
                .then(function(response) {
                    me.setToken(response.data, !!options.persistent);
                    me._resolveAllPendingRequest(true, arguments)
                }, function() {
                    me._resolveAllPendingRequest(false, arguments)
                });
        } else {
            me._addPendingRequest(deferred);
        }
        return deferred.promise;
    }

    function _authorizeRequest(requestConfig, responseError) {
        var deferred = $q.defer();
        var me = this;

        function continueRequest(access_token) {
            if (access_token) {
                requestConfig.headers['Authorization'] = 'Bearer ' + access_token;
            }
            deferred.resolve(requestConfig);
        }

        function abortRequest() {
            !responseError ? continueRequest() : deferred.reject(responseError);
        }

        function isBadRefreshToken(response) {
            return response[1] === 400 && response[0].error === "invalid_grant";
        }

        function requestCredentials() {
            //console.log("Credentials requested: " + me.options.url);

            //Se a função foi definida supoe-se resourceOwnerCredentials
            if (!me.options.resourceOwnerCredentialsFn) {
                // Se não está configurado o cliente 
                if (me.options.client_id) {
                    if (me.options.clientCredentialsFn) {
                        me.options.clientCredentialsFn();
                    } else {
                        continueRequest();
                    }
                } else {
                    //selfAuthorize
                    me.authorize()
                        .then(function() {
                            continueRequest(me.access_token);
                        }, function() {
                            abortRequest();
                        });
                }

            } else {
                abortRequest();
                me.options.resourceOwnerCredentialsFn(me.options);
            }
        }

        this.getToken().then(function(access_token) {
            continueRequest(access_token);
        }, function(response) {
            if (response === "REQUEST_CREDENTIALS" || isBadRefreshToken(response)) {
                requestCredentials();
            } else {
                abortRequest();
            }
        })

        //abortRequest();
        return deferred.promise;
    };

    function _addPendingRequest(deferred) {
        var me = this;
        me._pendingRequests = me._pendingRequests || [];
        me._pendingRequests.push(deferred);
    };

    function _hasPendingRequests() {
        var me = this;
        return (me._pendingRequests || []).length > 0;
    };

    function _resolveAllPendingRequest(isSuccess, arglist) {
        var me = this;
        (me._pendingRequests || []).map(function(deferred) {
            deferred[isSuccess ? "resolve" : "reject"].call(deferred, arglist);
        });
        delete me._pendingRequests;
    };

    function extend(dst) {
        for (var i = 1, ii = arguments.length; i < ii; i++) {
            var obj = arguments[i];
            if (obj) {
                var keys = Object.keys(obj);
                for (var j = 0, jj = keys.length; j < jj; j++) {
                    var key = keys[j];
                    dst[key] = obj[key];
                }
            }
        }
        return dst;
    };
}));