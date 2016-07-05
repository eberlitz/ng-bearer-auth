function extend() {
    var args = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        args[_i - 0] = arguments[_i];
    }
    var dst = args[0];
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
}
;
var AuthService = (function () {
    function AuthService(options) {
        this.options = options;
        this.isPersistent = !!AuthService.$storage.getItem(options.name + "-isPersistent");
        this.options = extend(options, {
            clientCredentialsFn: function (authService, options) {
                return authService.authorize();
            }
        });
    }
    AuthService.prototype.authorize = function (options, config) {
        var me = this;
        options = extend({
            authorizeUrl: me.options.url + 'token'
        }, me.options, options);
        var deferred = AuthService.$q.defer();
        var data = {
            grant_type: options.username ? 'password' : 'client_credentials',
            username: options.username,
            password: options.password,
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        if (options.scope) {
            data.scope = encodeURIComponent(options.scope.join(' '));
        }
        var body = [];
        for (var prop in data) {
            if (data[prop] != null) {
                body.push(prop + '=' + data[prop]);
            }
        }
        config = extend({
            ignoreAuthInterceptor: true
        }, config);
        AuthService.$http.post(options.authorizeUrl, body.join('&'), config)
            .then(function (response) {
            me.setToken(response.data, !!options.persistent);
            deferred.resolve(response.data);
        }, function (response) {
            deferred.reject(response.data);
        });
        return deferred.promise;
    };
    AuthService.prototype.removeToken = function () {
        var me = this;
        var propsToRemove = ['access_token', 'refresh_token', 'expires_at'];
        propsToRemove.map(function (prop) {
            AuthService.$storage.removeItem(me.options.name + '-' + prop, me.isPersistent);
        });
    };
    AuthService.prototype.removeAccessToken = function () {
        var me = this;
        AuthService.$storage.removeItem(me.options.name + '-access_token', me.isPersistent);
        this.access_token = undefined;
    };
    AuthService.prototype.isAuthenticated = function () {
        return this._hasRefreshToken() || this._hasAccessToken();
    };
    AuthService.prototype._hasRefreshToken = function () {
        this.refresh_token = this._getData('refresh_token');
        return !!this.refresh_token;
    };
    AuthService.prototype.getRefreshToken = function () {
        if (this._hasRefreshToken()) {
            return this.refresh_token;
        }
        ;
        return null;
    };
    AuthService.prototype._hasAccessToken = function () {
        var me = this;
        var now = new Date().getTime();
        var expires_at = me._getData('expires_at');
        if (now < expires_at) {
            me.access_token = me._getData('access_token');
        }
        else {
            me.access_token = undefined;
        }
        return !!me.access_token;
    };
    AuthService.prototype._getData = function (propName) {
        var me = this;
        propName = me.options.name + '-' + propName;
        return AuthService.$storage.getItem(propName);
    };
    AuthService.prototype.setToken = function (tokenData, isPersistent) {
        var me = this;
        if (typeof me.isPersistent !== 'undefined' && me.isPersistent !== !!isPersistent) {
            me.removeToken();
        }
        me.isPersistent = !!isPersistent;
        AuthService.$storage.setItem(me.options.name + "-isPersistent", me.isPersistent, true);
        var now = new Date().getTime();
        var expiresAt = now + parseInt(tokenData.expires_in, 10) * 1000 - 30000;
        var toStore = {
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token || me._getData('refresh_token'),
            expires_at: expiresAt
        };
        for (var prop in toStore) {
            AuthService.$storage.setItem(me.options.name + '-' + prop, toStore[prop], me.isPersistent);
        }
        me.access_token = toStore.access_token;
        me.refresh_token = toStore.refresh_token;
    };
    AuthService.prototype._requestAccessToken = function () {
        var me = this;
        var deferred = AuthService.$q.defer();
        var options = extend({
            persistent: me.isPersistent
        }, {
            authorizeUrl: me.options.url + 'token'
        }, me.options);
        var data = {
            grant_type: 'refresh_token',
            refresh_token: me.refresh_token,
            client_id: options.clientId,
            client_secret: options.clientSecret
        };
        var body = [];
        for (var prop in data) {
            if (data[prop] != null) {
                body.push(prop + '=' + data[prop]);
            }
            ;
        }
        ;
        var refreshUrl = options.authorizeUrl;
        if (!me._hasPendingRequests()) {
            me._addPendingRequest(deferred);
            AuthService.$http.post(refreshUrl, body.join('&'), {
                ignoreAuthInterceptor: true
            })
                .then(function (response) {
                me.setToken(response.data, !!options.persistent);
                me._resolveAllPendingRequest(true, arguments);
            }, function () {
                me._resolveAllPendingRequest(false, arguments);
            });
        }
        else {
            me._addPendingRequest(deferred);
        }
        return deferred.promise;
    };
    AuthService.prototype._requestCredentials = function () {
        var deferred = AuthService.$q.defer();
        var isPromise = function (object) { return object && typeof object.then === 'function'; };
        if (this.options.resourceOwnerCredentialsFn) {
            var roCredentials = this.options.resourceOwnerCredentialsFn ? this.options.resourceOwnerCredentialsFn(this.options) : undefined;
            if (isPromise(roCredentials)) {
                roCredentials.then(function () { return deferred.resolve(); }, function () { return deferred.reject(); });
            }
            else {
                deferred.reject();
            }
        }
        else if (this.options.clientId && this.options.clientSecret) {
            var cliCredentials = this.options.clientCredentialsFn ? this.options.clientCredentialsFn(this, this.options) : undefined;
            if (isPromise(cliCredentials)) {
                cliCredentials.then(function () { return deferred.resolve(); }, function () { return deferred.reject(); });
            }
            else {
                deferred.reject();
            }
        }
        else {
            deferred.reject();
        }
        return deferred.promise;
    };
    AuthService.prototype._authorizeRequest = function (httpConfig) {
        var _this = this;
        var deferred = AuthService.$q.defer();
        var continueRequest = function (access_token) {
            if (access_token) {
                httpConfig.headers['Authorization'] = 'Bearer ' + access_token;
            }
            deferred.resolve(httpConfig);
        };
        var isBadRefreshToken = function (response) {
            return response[0].status === 400 && response[0].data && response[0].data.error === 'invalid_grant';
        };
        if (this._hasAccessToken()) {
            httpConfig[AuthService.TRATAR_401] = true;
            continueRequest(this.access_token);
        }
        else {
            this.removeAccessToken();
            if (this._hasRefreshToken()) {
                this._requestAccessToken()
                    .then(function () {
                    continueRequest(_this.access_token);
                }, function (response) {
                    if (isBadRefreshToken(response)) {
                        _this.removeToken();
                        _this._requestCredentials()
                            .then(function () {
                            continueRequest(_this.access_token);
                        }, function () {
                            continueRequest();
                        });
                    }
                    else {
                        continueRequest();
                    }
                });
            }
            else {
                this._requestCredentials()
                    .then(function () {
                    continueRequest(_this.access_token);
                }, function () {
                    continueRequest();
                });
            }
        }
        return deferred.promise;
    };
    AuthService.prototype._addPendingRequest = function (deferred) {
        var me = this;
        me._pendingRequests = me._pendingRequests || [];
        me._pendingRequests.push(deferred);
    };
    AuthService.prototype._hasPendingRequests = function () {
        var me = this;
        return (me._pendingRequests || []).length > 0;
    };
    AuthService.prototype._resolveAllPendingRequest = function (isSuccess, arglist) {
        var me = this;
        (me._pendingRequests || []).map(function (deferred) {
            deferred[isSuccess ? 'resolve' : 'reject'].call(deferred, arglist);
        });
        delete me._pendingRequests;
    };
    AuthService.TRATAR_401 = 'authInterceptorRecoverFrom401';
    return AuthService;
}());
var AuthFactory = (function () {
    function AuthFactory(AuthService) {
        this.AuthService = AuthService;
        this.configs = {};
    }
    AuthFactory.prototype.configure = function (options) {
        var name = options.name = options.name || 'default';
        if (name in this.configs) {
            throw 'name ' + name + ' is already taken!';
        }
        return this.configs[name] = new this.AuthService(options);
    };
    AuthFactory.prototype.get = function (name) {
        if (typeof name !== 'string') {
            throw 'Expected name to be a string! Found: ' + typeof name + '.';
        }
        var config = this.configs[name];
        if (config) {
            return config;
        }
        ;
        return this.configs['default'];
    };
    AuthFactory.prototype.getByUrl = function (url) {
        if (typeof url !== 'string') {
            throw 'Expected url to be a string! Found: ' + typeof url + '.';
        }
        for (var u in this.configs) {
            var config = this.configs[u];
            if (!!config.options.url && url.indexOf(config.options.url) === 0) {
                return config;
            }
            ;
        }
        ;
        return null;
    };
    AuthFactory.$inject = [
        '$$authService'
    ];
    return AuthFactory;
}());
var appStorage = function ($window) {
    if (isLocalStorageAllowed()) {
        return $window.localStorage;
    }
    else {
        return $window.sessionStorage;
    }
    function isLocalStorageAllowed() {
        var mod = "test";
        try {
            $window.localStorage.setItem(mod, mod);
            $window.localStorage.removeItem(mod);
            return true;
        }
        catch (e) {
            return false;
        }
    }
};
appStorage.$inject = ['$window'];
var AuthStorage = (function () {
    function AuthStorage($window, appStorage) {
        this.$window = $window;
        this.appStorage = appStorage;
    }
    AuthStorage.prototype.getItem = function (name) {
        var value = this.$window.sessionStorage.getItem(name) || this.appStorage.getItem(name);
        return angular.fromJson(value);
    };
    AuthStorage.prototype.removeItem = function (name, isPersistent) {
        var storage = isPersistent ? this.appStorage : this.$window.sessionStorage;
        return storage.removeItem(name);
    };
    AuthStorage.prototype.setItem = function (name, value, isPersistent) {
        var storage = isPersistent ? this.appStorage : this.$window.sessionStorage;
        return storage.setItem(name, angular.toJson(value));
    };
    AuthStorage.$inject = [
        '$window',
        'appStorage'
    ];
    return AuthStorage;
}());
var AuthServiceInterceptor = (function () {
    function AuthServiceInterceptor() {
    }
    AuthServiceInterceptor.prototype.request = function (httpConfig) {
        httpConfig.headers = httpConfig.headers || {};
        if (httpConfig.url && !httpConfig.headers['Authorization'] && !httpConfig['ignoreAuthInterceptor']) {
            this.$authProvider = this.$authProvider || AuthServiceInterceptor.$injector.get('$authProvider');
            var $auth = this.$authProvider.getByUrl(httpConfig.url);
            if (!$auth) {
                return httpConfig || AuthServiceInterceptor.$q.when(httpConfig);
            }
            return $auth._authorizeRequest(httpConfig);
        }
        return httpConfig;
    };
    AuthServiceInterceptor.prototype.responseError = function (rejection) {
        if (rejection.status === 401 && rejection.config && rejection.config[AuthService.TRATAR_401] === true) {
            this.$authProvider = this.$authProvider || AuthServiceInterceptor.$injector.get('$authProvider');
            var $auth = this.$authProvider.getByUrl(rejection.config.url);
            if ($auth) {
                $auth.removeAccessToken();
                delete rejection.config[AuthService.TRATAR_401];
                delete rejection.config.headers['Authorization'];
                this.$http = this.$http || AuthServiceInterceptor.$injector.get('$http');
                return AuthServiceInterceptor.$q.resolve(this.$http(rejection.config));
            }
        }
        return AuthServiceInterceptor.$q.reject(rejection);
    };
    return AuthServiceInterceptor;
}());
angular.module('ngBearerAuth.storage', [])
    .factory('appStorage', appStorage);
angular.module('ngBearerAuth', ['ngBearerAuth.storage'])
    .service('$$storage', AuthStorage)
    .factory('$$authService', ['$q', '$http', '$$storage', function ($q, $http, $storage) {
        AuthService.$q = $q;
        AuthService.$http = $http;
        AuthService.$storage = $storage;
        return AuthService;
    }])
    .service('$authProvider', AuthFactory)
    .factory('$auth', ['$authProvider', function ($authProvider) { return $authProvider.get('default'); }])
    .factory('$authServiceInterceptor', ['$injector', '$q', function ($injector, $q) {
        AuthServiceInterceptor.$injector = $injector;
        AuthServiceInterceptor.$q = $q;
        return new AuthServiceInterceptor();
    }]);
angular.module('ngBearerAuthInterceptor', ['ngBearerAuth'])
    .config(['$httpProvider', function ($httpProvider) { return $httpProvider.interceptors.push('$authServiceInterceptor'); }]);
//# sourceMappingURL=ng-bearer-auth.js.map