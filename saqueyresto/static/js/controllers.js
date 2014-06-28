var phonecatApp = angular.module('phonecatApp', ['ngResource']);

phonecatApp.controller('PhoneListCtrl', function ($scope, $http) {
  $http.get('api/profiles/').success(function(data) {
    $scope.profiles = data;
  });
});


