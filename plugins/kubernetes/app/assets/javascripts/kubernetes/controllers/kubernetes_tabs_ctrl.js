samson.controller('KubernetesTabsCtrl', function($rootScope, $scope) {

  $rootScope.$on('$stateChangeSuccess', function(event, toState, toParams) {
    $scope.currentTab = toState.data.selectedTab;
    $scope.project_id = toParams.project_id;
  });
});