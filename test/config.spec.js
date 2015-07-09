describe('ngBearerAuth', function() {

    beforeEach(function() {
        var self = this;
        module('ngBearerAuth', ['$authProvider', function($authProvider) {
            self.$authProvider = $authProvider;
        }]);
    });

    it('should be defined', function() {
        expect(this.$authProvider).toBeDefined();
    });

});