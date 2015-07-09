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
        return {
            $get: AuthService,
            configure: configure
        };
        //--------------------------------------------------------
        function configure(options) {
            throw 'Not Implemented!'
        }

        function AuthService($q) {
            return {
                configure: configure,
                get: get,
                getByUrl: getByUrl
            };
            //--------------------------------------------------------
            function get() {
                throw 'Not Implemented!'
            }

            function getByUrl() {
                throw 'Not Implemented!'
            }
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