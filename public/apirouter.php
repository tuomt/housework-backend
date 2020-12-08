<?php
require __DIR__ . '/../priv/config/ExceptionHandler.php';
set_exception_handler("ExceptionHandler::handle");
set_error_handler("ExceptionHandler::handleError");
ini_set('display_errors', 1);
error_reporting(E_ALL);
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../priv/config/Database.php';
require __DIR__ . '/../priv/config/JsonValidator.php';
require __DIR__ . '/../priv/config/TokenManager.php';
require __DIR__ . '/../priv/controllers/UserController.php';
require __DIR__ . '/../priv/controllers/GroupController.php';
require __DIR__ . '/../priv/controllers/GroupMemberController.php';
require __DIR__ . '/../priv/controllers/TaskController.php';

$router = new AltoRouter();

// Requests related to users
$router->map('GET', '/api/users/[i:id]', 'UserController::getUser');
$router->map('POST', '/api/users', 'UserController::createUser');
$router->map('PATCH', '/api/users/[i:id]', 'UserController::modifyUserPartially');
$router->map('DELETE', '/api/users/[i:id]', 'UserController::deleteUser');
// Route for getting a new access token
$router->map('POST', '/api/users/[i:id]/access-token', 'UserController::getNewAccessToken');

// Map authentication URIs
$router->map('POST', '/api/credentials/user', 'UserController::authenticateUser');
$router->map('POST', '/api/credentials/group', 'GroupMemberController::authenticateGroupMember');

// Requests related to groups
$router->map('GET', '/api/groups/[i:id]', 'GroupController::getGroup');
$router->map('POST', '/api/groups', 'GroupController::createGroup');
$router->map('PATCH', '/api/groups/[i:id]', 'GroupController::modifyGroupPartially');
$router->map('DELETE', '/api/groups/[i:id]', 'GroupController::deleteGroup');

// Requests related to group members
$router->map('POST', '/api/groups/[i:groupid]/members', 'GroupMemberController::createMember');
$router->map('GET', '/api/groups/[i:groupid]/members', 'GroupMemberController::getMembers');
$router->map('DELETE', '/api/groups/[i:groupid]/members/[i:userid]', 'GroupMemberController::deleteMember');

// Routing for requests related to tasks
$router->map('POST', '/api/groups/[i:groupid]/tasks', 'TaskController::createTask');
$router->map('GET', '/api/groups/[i:groupid]/tasks', 'TaskController::getTasks');

$match = $router->match();

if ($match === false) {
    header('Content-Type: application/json');
    http_response_code(404);
    $details = 'Page does not exist or the HTTP-method is not supported by this resource.';
    echo new ApiError('page_not_found', $details);
} else {
    $stmt = call_user_func_array($match['target'], $match['params']);
}

