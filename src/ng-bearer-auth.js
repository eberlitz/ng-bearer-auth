(function() {
    'use strict';
    angular.module('ngBearerAuth', [
            'ngBearerAuth.service'
        ])
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
            return null; //configs["default"];
        }
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