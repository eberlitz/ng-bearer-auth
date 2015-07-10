describe('$authProvider', function() {
    beforeEach(module('ngBearerAuth'));

    beforeEach(inject(['$window', '$httpBackend', '$authProvider', 
    	function($window, $httpBackend, $authProvider) {
        this.$window = $window;
        this.$httpBackend = $httpBackend;
        this.$authProvider = $authProvider;
    }]));

    it('should be defined', function() {
        expect(this.$authProvider).toBeDefined();
    });

     it('configure should be defined', function() {
        expect(this.$authProvider.configure).toBeDefined();
    });
});