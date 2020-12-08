<?php

//require __DIR__ . "/../config/JsonValidator.php";
require __DIR__ . '/../config/ApiError.php';

class UserController
{
    const TABLE_NAME = "users";
    const MIN_NAME_LEN = 2;
    const MAX_NAME_LEN = 21;
    const MIN_PASSWORD_LEN = 8;
    const MAX_PASSWORD_LEN = 85;
    const MIN_EMAIL_LEN = 5;
    const MAX_EMAIL_LEN = 85;

    // All resources
    const RESOURCES = array(
        'name' => JsonValidator::T_STRING,
        'password' => JsonValidator::T_STRING_NULLABLE,
        'email' => JsonValidator::T_STRING_NULLABLE
    );

    // These resources can be modified with a PATCH-request
    // TODO: make name patchable
    const PATCHABLE_RESOURCES = array(
        'password' => JsonValidator::T_STRING_NULLABLE,
        'email' => JsonValidator::T_STRING_NULLABLE
    );

    // These resources are used for authentication
    const AUTHENTICATION_RESOURCES = array(
        'email' => JsonValidator::T_STRING,
        'password' => JsonValidator::T_STRING_NULLABLE,
    );

    static function authenticateUser()
    {
        header('Content-Type: application/json');

        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if the data is valid
        $dataValidationError = JsonValidator::validateData($data, self::AUTHENTICATION_RESOURCES,
            true);
        if ($dataValidationError !== null) {
            http_response_code(400);
            echo $dataValidationError;
            return false;
        }

        // Build a query
        $query = "SELECT id, password FROM " . self::TABLE_NAME . " WHERE email = :email";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind email
        $statement->bindParam(':email', $data["email"]);

        // Execute the statement and fetch user information
        if ($statement->execute()) {
            $user = $statement->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Verify password
                if (password_verify($data["password"], $user["password"]))
                {
                    // Create an access token and a refresh token
                    $accessToken = TokenManager::createAccessToken($user["id"]);
                    $refreshToken = TokenManager::createRefreshToken($user["id"]);
                    // Send the tokens to the client
                    http_response_code(200);
                    echo json_encode(array(
                        "id" => $user["id"],
                        "accesstoken" => $accessToken,
                        "refreshtoken" => $refreshToken
                    ));
                    return true;
                } else {
                    // Wrong password
                    http_response_code(401);
                    echo new ApiError('incorrect_password');
                    return false;
                }
            } else {
                // User not found
                http_response_code(404);
                $details = 'A user with the requested email does not exist.';
                echo new ApiError('user_not_found', $details);
                return false;
            }
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function fetchAllGroups($userid, $fetchStyle = PDO::FETCH_ASSOC) {
        $query = "SELECT * FROM " . GroupMemberController::TABLE_NAME . " WHERE userid = :userid";
        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        // Execute the statement and fetch user information
        $statement->execute();
        return $statement->fetchAll($fetchStyle);
    }

    static function getNewAccessToken($id) {
        header('Content-Type: application/json');

        // Get refresh token
        $refreshToken = TokenManager::getDecodedRefreshToken();

        // Authorize
        if ($refreshToken instanceOf ApiError) {
            // Authorization failed
            http_response_code(401);
            echo $refreshToken;
            return false;
        } else if ($refreshToken->data->userid != $id) {
            // Permission denied
            http_response_code(403);
            echo new ApiError('permission_denied');
            return false;
        }

        // Create an access token
        $accessToken = TokenManager::createAccessToken($id);
        // Send the token to the client
        http_response_code(200);
        echo json_encode(array("accesstoken" => $accessToken));
        return true;
    }

    static function getUser($id) {
        header('Content-Type: application/json');
        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Authorize
        if ($accessToken instanceOf ApiError) {
            // Authorization failed
            http_response_code(401);
            echo $accessToken;
            return false;
        } else if ($accessToken->data->userid != $id) {
            // Permission denied
            http_response_code(403);
            echo new ApiError('permission_denied');
            return false;
        }

        // Build a query
        $query = "SELECT id, name, email FROM " . self::TABLE_NAME . " WHERE id = :id";

        // Connect to database and prepare the query
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindParam(':id', $id, PDO::PARAM_INT);

        // Execute the statement
        if ($statement->execute()) {
            // Fetch user
            $user = $statement->fetch(PDO::FETCH_ASSOC);

            // Send a response
            if ($user) {
                http_response_code(200);
                echo json_encode($user);
                return true;
            } else {
                http_response_code(404);
                $details = 'A user with the requested id does not exist.';
                echo new ApiError('user_not_found', $details);
                return false;
            }
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function createUser() {
        header('Content-Type: application/json');

        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, self::RESOURCES, true);
        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Check if the input meets requirements
        $requirementError = self::testRequirements($data);
        if ($requirementError !== null) {
            http_response_code(422);
            echo $requirementError;
            return false;
        }

        // Build the query
        $query = "INSERT INTO " . self::TABLE_NAME . " VALUES (null, :name, :password, :email)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Create hash from the password
        $passwordHash = password_hash($data["password"], PASSWORD_DEFAULT);
        // Bind params
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':password', $passwordHash, PDO::PARAM_STR);
        $statement->bindParam(':email', $data["email"], PDO::PARAM_STR);

        // Send a response depending on the outcome of the query
        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array(
                "id" => (int)$conn->lastInsertId(),
                "name" => $data["name"],
                "email" => $data["email"]
            ));
            return true;
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError("database_query_failed");
            return false;
        }
    }

    static function modifyUserPartially($id) {
        header('Content-Type: application/json');

        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Authorize
        if ($accessToken instanceOf ApiError) {
            // Authorization failed
            http_response_code(401);
            echo $accessToken;
            return false;
        } else if ($accessToken->data->userid != $id) {
            // Permission denied
            http_response_code(403);
            echo new ApiError('permission_denied');
            return false;
        }

        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, self::PATCHABLE_RESOURCES, false);
        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Check if the input meets requirements
        $requirementError = self::testRequirements($data);
        if ($requirementError !== null) {
            http_response_code(422);
            echo $requirementError;
            return false;
        }

        // Build the query
        $query = "UPDATE " . self::TABLE_NAME . " SET ";
        $keyCount = count($data);
        $keyIndex = 0;
        foreach ($data as $key => $value) {
            $query .= "$key = ?";
            if ($keyIndex < ($keyCount - 1)) {
                $query .= ", ";
            }
            $keyIndex++;
        }
        $query .= " WHERE id = ?";

        // Connect to the database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);

        // Bind values
        $valueIndex = 1;
        foreach ($data as $key => $value) {
            if (strcmp($key, "password") === 0) {
                if (!is_null($value)) {
                    // Create a hash from the password
                    $value = password_hash($value, PASSWORD_DEFAULT);
                }
            }

            // Select the correct data type for binding the value
            if (is_int($value)) {
                $valueType = PDO::PARAM_INT;
            }
            else if (is_string($value)) {
                $valueType = PDO::PARAM_STR;
            } else $valueType = PDO::PARAM_NULL;

            $statement->bindValue($valueIndex, $value, $valueType);
            $valueIndex++;
        }
        $statement->bindValue($valueIndex, $id, PDO::PARAM_INT);

        // Execute the statement
        if ($statement->execute()) {
            // Check if any rows were changed
            $changedRows = $statement->rowCount();
            if ($changedRows > 0) {
                http_response_code(204);
                return true;
            } else {
                http_response_code(404);
                $details = 'A user with the requested id does not exist.';
                echo new ApiError('user_not_found', $details);
                return false;
            }
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function deleteUser($id) {
        header('Content-Type: application/json');

        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Authorize
        if ($accessToken instanceOf ApiError) {
            // Authorization failed
            http_response_code(401);
            echo $accessToken;
            return false;
        } else if ($accessToken->data->userid != $id) {
            // Permission denied
            http_response_code(403);
            echo new ApiError('permission_denied');
            return false;
        }

        // Build the query
        $query = "DELETE FROM " . self::TABLE_NAME . " WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindValue(':id', $id, PDO::PARAM_INT);

        // Execute the statement and send a response
        // execute() returns true if there was nothing to delete
        if ($statement->execute()) {
            if ($statement->rowCount() > 0) {
                http_response_code(204);
                return true;
            } else {
                http_response_code(404);
                $details = 'A user with the requested id does not exist.';
                echo new ApiError('user_not_found', $details);
                return false;
            }
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError("database_query_failed");
            return false;
        }
    }

    private static function testRequirements(&$data) {
        /*
         * Test if data meets requirements.
         * The data is passed as a reference and may be modified in the following way:
         * - Whitespace is stripped from beginning and end of the string values (except passwords)
         *   before the test.
         *
         * The following conditions are checked:
         * - The string values cannot be empty strings or only consist of whitespace
         * - The value of 'name' must be at least MIN_NAME_LEN characters long
         * - The value of 'name' must be at most MAX_NAME_LEN characters long
         * - The value of 'password' must be at least MIN_PASSWORD_LEN characters long
         * - The value of 'password' must be at most MAX_PASSWORD_LEN characters long
         * - The value of 'email' must be at least MIN_EMAIL_LEN characters long
         * - The value of 'email' must be at most MAX_EMAIL_LEN characters long
         *
         * Returns null if all requirements are met,
         * otherwise returns an ApiError object.
         */

        if (array_key_exists("name", $data)) {
            $data["name"] = trim($data["name"]);

            $lenDifference = JsonValidator::checkStringLength($data["name"],
                self::MIN_NAME_LEN,
                self::MAX_NAME_LEN);

            if ($lenDifference !== 0) {
                $details = null;

                if ($lenDifference < 0) {
                    $details = "The value of 'name' is too short.";
                } else if ($lenDifference > 0) {
                    $details = "The value of 'name' is too long.";
                }
                return new ApiError("invalid_username", $details);
            }
        }

        if (array_key_exists("password", $data)) {
            $lengthDifference = JsonValidator::checkStringLength($data["password"],
                self::MIN_PASSWORD_LEN,
                self::MAX_PASSWORD_LEN);

            if ($lengthDifference !== 0) {
                $details = null;

                if ($lengthDifference < 0) {
                    $details = "The value of 'password' is too short.";
                } else if ($lengthDifference > 0) {
                    $details = "The value of 'password' is too long.";
                }
                return new ApiError("invalid_password", $details);
            }
        }

        if (array_key_exists("email", $data)) {
            $data["email"] = trim($data["email"]);

            $lengthDifference = JsonValidator::checkStringLength($data["email"],
                self::MIN_EMAIL_LEN,
                self::MAX_EMAIL_LEN);

            if ($lengthDifference !== 0) {
                $details = null;

                if ($lengthDifference < 0) {
                    $details = "The value of 'email' is too short.";
                } else if ($lengthDifference > 0) {
                    $details = "The value of 'email' is too long.";
                }
                return new ApiError("invalid_email", $details);
            }
        }

        return null;
    }
}