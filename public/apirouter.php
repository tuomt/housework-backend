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

$router = new AltoRouter();

// Requests related to users
$router->map('GET', '/api/users/[i:id]', 'UserController::getUser');
$router->map('POST', '/api/users', 'UserController::createUser');
$router->map('PATCH', '/api/users/[i:id]', 'UserController::modifyUserPartially');
$router->map('DELETE', '/api/users/[i:id]', 'UserController::deleteUser');

// Tokens
$router->map('POST', '/api/tokens', 'UserController::authenticateUser');
$router->map('POST', '/api/users/[i:id]/access-token', 'UserController::getNewAccessToken');

// Requests related to groups
$router->map('GET', '/api/groups/[i:id]', 'GroupController::getGroup');
$router->map('POST', '/api/groups', 'GroupController::createGroup');
$router->map('PUT', '/api/groups/[i:id]', 'GroupController::modifyGroup');
$router->map('PATCH', '/api/groups/[i:id]', 'GroupController::modifyGroupPartially');
$router->map('DELETE', '/api/groups/[i:id]', 'GroupController::deleteGroup');

// TODO: Requests related to tasks

$match = $router->match();

if ($match === false) {
    header('Content-Type: application/json');
    http_response_code(404);
    echo json_encode(array("errormessage" => "Page not found or the HTTP-method is not supported for this page."));
} else {
    $stmt = call_user_func_array($match['target'], $match['params']);
}

