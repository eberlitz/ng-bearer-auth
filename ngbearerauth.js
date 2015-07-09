(function() {
    'use strict';
    angular.module('ngBearerAuth', [])
        .provider('$auth', AuthProvider)
        .factory('$authService', AuthService)
        .factory('$authServiceInterceptor', AuthServiceInterceptor);

    angular.module('ngBearerAuthInterceptor', ['ngBearerAuth'])
        .config(function($httpProvider) {
            $httpProvider.interceptors.push('$authServiceInterceptor');
        });
    //--------------------------------------------------------
    function AuthProvider() {
        var configs = {};
        return {
            configure: configure,
            $get: function($injector) {
                return $injector.invoke(AuthService).get('default');
            }
        };
        //--------------------------------------------------------
        function configure(options) {
            var name = options.name || "default";
            if (name in configs) {
                throw 'name ' + name + ' is already taken!';
            }
            configs[name] = new $auth(name, options);
            configs[name].destroy = function() {
                delete configs[this.name];
            };
        }

        function AuthService($q) {
            return {
                configure: configure,
                get: get,
                getByUrl: getByUrl
            };
            //--------------------------------------------------------
            function get(name) {
                name = name || 'default';
                throw 'Not Implemented!'
            }

            function getByUrl() {
                throw 'Not Implemented!'
            }
        }


        function $auth(name, options) {
            this.name = name;
            this.options = options;
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
            this.authorize = function(options) {

            };

            // Removes authorization tokens from Storage.
            this.removeToken = function() {

            };

            // Returns true if an refresh token or access token is present in Storage and it is not expired, otherwise returns false.
            this.isAuthenticated = function() {

            };

            // Returns an access token from the Storage if it is not expired. If there is an Refresh Token in Storage exchange it for an access token within the server.
            this.getToken = function() {

            };

            // Saves an authorization token to Storage.
            // string tokenData.access_token
            // string [tokenData.refresh_token]
            this.setToken = function(tokenData) {

            };

            this._authorizeRequest = function(requestConfig) {
                return $q.when(requestConfig);
            };
        }
    }
    // ----------------------------------------------------------------
    function AuthServiceInterceptor($injector, $q) {
        return {
            request: function(httpConfig) {
                return httpConfig;
            },
            responseError: function(response) {
                return $q.reject(response);
            }
        };
    }

})(window, window.angular);