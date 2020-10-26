<?php

//require __DIR__ . "/../config/JsonValidator.php";
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
        'groupid' => JsonValidator::T_INT_NULLABLE,
        'name' => JsonValidator::T_STRING,
        'password' => JsonValidator::T_STRING_NULLABLE,
        'master' => JsonValidator::T_INT,
        'email' => JsonValidator::T_STRING_NULLABLE
    );

    // These resources can be modified with a PATCH-request
    const PATCHABLE_RESOURCES = array(
        'groupid' => JsonValidator::T_INT_NULLABLE,
        'password' => JsonValidator::T_STRING_NULLABLE,
        'master' => JsonValidator::T_INT,
        'email' => JsonValidator::T_STRING_NULLABLE
    );

    // These resources are used for authentication
    const AUTHENTICATION_RESOURCES = array(
        'name' => JsonValidator::T_STRING,
        'password' => JsonValidator::T_STRING_NULLABLE,
    );

    static function authenticateUser()
    {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $invalidDataMsg = "";
        $isDataValid = JsonValidator::validateData($data, self::AUTHENTICATION_RESOURCES, true, $invalidDataMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $invalidDataMsg"));
            return false;
        }

        // Check if user exists and the password is correct
        // TODO: user name must be unique, create alias column in users table
        $query = "SELECT id, password FROM " . self::TABLE_NAME . " WHERE name = :name";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind name
        $statement->bindParam(':name', $data["name"]);
        // Execute the statement and fetch user information
        $statement->execute();
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
                    "accesstoken" => $accessToken,
                    "refreshtoken" => $refreshToken
                    ));
                return true;
            } else {
                http_response_code(401);
                echo json_encode(array("errormessage" => "Wrong password."));
                return false;
            }
        } else {
            http_response_code(401);
            echo json_encode(array("errormessage" => "User with this name does not exist."));
            return false;
        }
    }

    static function getNewAccessToken($id) {
        header('Content-Type: application/json');
        $tokenVerificationError = "";
        $token = TokenManager::getDecodedRefreshToken($tokenVerificationError);
        if ($token === false || $token->data->userid != $id) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $tokenVerificationError"));
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

        $tokenVerificationError = "";
        $token = TokenManager::getDecodedAccessToken($tokenVerificationError);
        if (!$token || $token->data->userid != $id) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $tokenVerificationError"));
            return false;
        }

        // Build the query
        $query = "SELECT  id, groupid, name, master, email" .
            " FROM " . self::TABLE_NAME .
            " WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindParam(':id', $id, PDO::PARAM_INT);
        // Execute the statement and fetch user information
        $statement->execute();
        $user = $statement->fetch(PDO::FETCH_ASSOC);

        // Send a response
        if ($user) {
            http_response_code(200);
            echo json_encode($user);
            return true;
        } else {
            http_response_code(404);
            echo json_encode(array("errormessage" => "Could not find any matches."));
            return false;
        }
    }

    static function createUser() {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents("php://input"), true);
        // Check if data is valid
        $invalidDataMsg = "";
        $isDataValid = JsonValidator::validateData($data, self::RESOURCES, true, $invalidDataMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $invalidDataMsg"));
            return false;
        }
        // Check if data meets requirements
        $dataMeetsRequirements = self::testRequirements($data, $invalidDataMsg);
        if (!$dataMeetsRequirements) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received data does not meet the requirements. $invalidDataMsg"));
            return false;
        }

        // Build the query
        $query = "INSERT INTO " . self::TABLE_NAME .
            " VALUES (null, :groupid, :name, :password, :master, :email)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Create hash from the password
        $passwordHash = password_hash($data["password"], PASSWORD_DEFAULT);
        // Bind params
        $statement->bindParam(':groupid', $data["groupid"], PDO::PARAM_INT);
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':password', $passwordHash, PDO::PARAM_STR);
        $statement->bindParam(':master', $data["master"], PDO::PARAM_INT);
        $statement->bindParam(':email', $data["email"], PDO::PARAM_STR);

        // Send a response depending on the outcome of the query
        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array("message" => "User was created successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to create user."));
            return false;
        }
    }

    static function modifyUserPartially($id) {
        header('Content-Type: application/json');

        $tokenVerificationError = "";
        $token = TokenManager::getDecodedAccessToken($tokenVerificationError);
        if (!$token || $token->data->userid != $id) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $tokenVerificationError"));
            return false;
        }

        $data = json_decode(file_get_contents("php://input"), true);
        // Check if data is valid
        $invalidDataMsg = "";
        $isDataValid = JsonValidator::validateData($data, self::PATCHABLE_RESOURCES, false, $invalidDataMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $invalidDataMsg"));
            return false;
        }

        // Check if data meets requirements
        $dataMeetsRequirements = self::testRequirements($data, $invalidDataMsg);
        if (!$dataMeetsRequirements) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received data does not meet the requirements. $invalidDataMsg"));
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
        $statement->execute();

        // Check if the update was successful
        $changedRows = $statement->rowCount();
        if ($changedRows > 0) {
            http_response_code(200);
            echo json_encode(array("message" => "Updated user successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to update user."));
            return false;
        }
    }

    static function deleteUser($id) {
        header('Content-Type: application/json');

        $tokenVerificationError = "";
        $token = TokenManager::getDecodedAccessToken($tokenVerificationError);
        if (!$token || $token->data->userid != $id) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $tokenVerificationError"));
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
        $statement->execute();

        if ($statement->rowCount() > 0) {
            http_response_code(200);
            echo json_encode(array("message" => "Successfully deleted user."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to delete user."));
            return false;
        }
    }

    private static function testRequirements(&$data, &$outFailureMsg = null) {
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
         * Optionally, a reference to a variable can be passed as outFailureMsg,
         * which will be set to an appropriate failure message in case the requirements
         * are not met.
         */

        if (array_key_exists("name", $data)) {
            $data["name"] = trim($data["name"]);
            if (!JsonValidator::validateStringLength(
                $data["name"],
                self::MIN_NAME_LEN,
                self::MAX_NAME_LEN,
                "name",
                $outFailureMsg
            )) {
                return false;
            }
        }

        if (array_key_exists("password", $data) &&
            !is_null($data["password"])) {
            if (!JsonValidator::validateStringLength(
                $data["password"],
                self::MIN_PASSWORD_LEN,
                self::MAX_PASSWORD_LEN,
                "password",
                $outFailureMsg
            )) {
                return false;
            }
        }

        if (array_key_exists("email", $data) &&
            !is_null($data["email"])) {
            $data["email"] = trim($data["email"]);
            if (!JsonValidator::validateStringLength(
                $data["email"],
                self::MIN_EMAIL_LEN,
                self::MAX_EMAIL_LEN,
                "email",
                $outFailureMsg
            )) {
                return false;
            }
        }

        return true;
    }
}