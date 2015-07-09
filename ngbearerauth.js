(function() {
    'use strict';
    angular.module('ngBearerAuth', [])
        .factory('$authServiceInterceptor', AuthServiceInterceptor)

    .factory('$auth', function($authProvider) {
        var defaultConfig = $authProvider.get('default');
        // if (!defaultConfig) {
        //     defaultConfig = $authProvider.configure({});
        // };
        return defaultConfig;
    })

    .factory('$authProvider', function($$authService) {
        var configs = {};
        var Provider = {
            configure: configure,
            get: get,
            getByUrl: getByUrl
        };
        return Provider;
        // ---------------------------------------------------------------
        function configure(options) {
            var name = options.name = options.name || "default";
            if (name in configs) {
                throw 'name ' + name + ' is already taken!';
            }
            return configs[name] = new $$authService(options); //new AuthService(options);
        }

        function get(name) {
            if (!angular.isString(name)) {
                throw 'Expected name to be a string! Found: ' + typeof name + '.';
            }
            var config = configs[name];
            if (config) {
                return config;
            };
            return configs["default"];
        }

        function getByUrl(url) {
            if (!angular.isString(url)) {
                throw 'Expected url to be a string! Found: ' + typeof url + '.';
            }
            for (var u in configs) {
                var config = configs[u];
                if (!!config.options.url && url.indexOf(config.options.url) == 0) {
                    return config;
                };
            };
            return configs["default"];
        }
    })

    .factory('$$authService', function($q, $http, $window) {
        function AuthService(options) {
            var me = this;
            me.options = options;
        }
        AuthService.prototype.authorize = authorize;
        AuthService.prototype.removeToken = removeToken;
        AuthService.prototype.isAuthenticated = isAuthenticated;
        AuthService.prototype.getToken = getToken;
        AuthService.prototype.setToken = setToken;
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
        function authorize(options) {

            //console.log(this.options.name, 'authorize', this.options);
            var me = this;
            var options = angular.extend({
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

            config = angular.extend({
                ignoreAuthInterceptor: true
            }, config);

            $http.post(options.authorizeUrl, body.join("&"), config)
                .success(function(data) {
                    me.setToken(data, !!options.persistent);
                    deferred.resolve(data);
                })
                .error(function(data) {
                    deferred.reject(data);
                });

            return deferred.promise;
        }

        // Removes authorization tokens from Storage.
        function removeToken() {
            var me = this;
            var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;

            var propsToRemove = ["access_token", "refresh_token", "expires_at"];
            propsToRemove.map(function(prop) {
                storage.removeItem(me.options.name + '-' + prop);
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
            return $window.sessionStorage.getItem(propName) || $window.localStorage.getItem(propName);
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
            var storage = me.isPersistent ? $window.localStorage : $window.sessionStorage;



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
                storage.setItem(me.options.name + '-' + prop, toStore[prop]);
            }
            me.access_token = toStore.access_token;
            me.refresh_token = toStore.refresh_token;
        };

        function _requestAccessToken() {
            var me = this;
            var deferred = $q.defer();
            var options = angular.extend({
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
                    .success(function(response) {
                        me.setToken(response);
                        me._resolveAllPendingRequest(true, arguments)
                    })
                    .error(function() {
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
                    if (!me.options.client_id) {
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
    });

    angular.module('ngBearerAuthInterceptor', ['ngBearerAuth'])
        .config(function($httpProvider) {
            $httpProvider.interceptors.push('$authServiceInterceptor');
        });

    //--------------------------------------------------------

    // // ----------------------------------------------------------------
    function AuthServiceInterceptor($injector, $q) {
        var $authProvider;
        return {
            request: function(httpConfig) {
                httpConfig.headers = httpConfig.headers || {};
                //Executar interceptor somente quando não houver nenhum método de autorização registrado 
                if (httpConfig.url && !httpConfig.headers.Authorization && !httpConfig.ignoreAuthInterceptor) {
                    $authProvider = $authProvider || $injector.get('$authProvider');
                    var $auth = $authProvider.getByUrl(httpConfig.url);
                    if (!$auth) {
                        return httpConfig || $q.when(httpConfig);
                    }
                    return $auth._authorizeRequest(httpConfig);
                }
                return httpConfig;
            },
            responseError: function(response) {
                //return $q.reject("response");
                if (response.status === 401 && response.config) {
                    var $auth = $authProvider.getByUrl(response.config.url);
                    if ($auth) {
                        $auth.removeToken();
                        return $auth._authorizeRequest(response.config, response);
                    }
                }
                return $q.reject(response);
            }
        };
    }

})(window, window.angular);