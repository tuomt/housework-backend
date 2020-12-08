<?php
//require __DIR__ . '/../config/Database.php';
//require __DIR__ . "/../config/JsonValidator.php";

class GroupController
{
    const TABLE_NAME = "groups";
    const MIN_NAME_LEN = 3; // Minimum length for a group name
    const MAX_NAME_LEN = 21; // Maximum length for a group name (inclusive)
    const MIN_PASSWORD_LEN = 5; // Length of the group's password
    const MAX_PASSWORD_LEN = 85; // Length of the group's password (inclusive)

    // All resources
    const RESOURCES = array(
        'name' => JsonValidator::T_STRING,
        'password' => JsonValidator::T_STRING
    );

    const AUTHENTICATION_RESOURCES = self::RESOURCES;

    static function fetchGroupById($id, $fetchStyle=PDO::FETCH_ASSOC) {
        $query = "SELECT * FROM " . self::TABLE_NAME . " WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindParam(':id', $id, PDO::PARAM_INT);
        // Execute the statement and fetch group information
        $statement->execute();
        return $statement->fetch($fetchStyle);
    }

    static function fetchGroup($name, $fetchStyle=PDO::FETCH_ASSOC) {
        $query = "SELECT * FROM " . self::TABLE_NAME . " WHERE name = :name";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind name
        $statement->bindParam(':name', $name, PDO::PARAM_STR);
        // Execute the statement and fetch group information
        $statement->execute();
        return $statement->fetch($fetchStyle);
    }

    static function getGroup($id) {
        header('Content-Type: application/json');

        // Check if the user has permission to access this resource
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, false);
        if ($isAuthorized === false) {
            return false;
        }

        // Build the query
        $query = "SELECT id, creatorid, name FROM " . self::TABLE_NAME .
                 " WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindParam(':id', $id, PDO::PARAM_INT);

        // Execute the statement
        if ($statement->execute()) {
            $group = $statement->fetch(PDO::FETCH_ASSOC);
            // Send a response
            if ($group) {
                http_response_code(200);
                echo json_encode($group);
                return true;
            } else {
                http_response_code(404);
                $details = 'A group with this id does not exist.';
                echo new ApiError('group_not_found', $details);
                return false;
            }
        } else {
            http_response_code(500);
            $details = "An error occurred while trying to fetch group information.";
            echo new ApiError('database_query_failed', $details);
            return false;
        }
    }

    static function createGroup() {
        header('Content-Type: application/json');

        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Authorize
        if ($accessToken instanceOf ApiError) {
            // Authorization failed
            http_response_code(401);
            echo $accessToken;
            return false;
        }

        // Get user id from the access token
        $userid = $accessToken->data->userid;

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
        $query = "INSERT INTO " . self::TABLE_NAME . " VALUES (null, :creatorid, :name, :password)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Create hash from the password
        $passwordHash = password_hash($data["password"], PASSWORD_DEFAULT);
        // Bind params
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':password', $passwordHash, PDO::PARAM_STR);
        $statement->bindParam(':creatorid', $userid, PDO::PARAM_INT);

        // Send a response depending on the outcome of the query
        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array(
                "id" => (int)$conn->lastInsertId(),
                "creatorid" => (int)$userid,
                "name" => $data["name"]
            ));
            return true;
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError("database_query_failed");
            return false;
        }
    }

    static function modifyGroupPartially($id) {
        header('Content-Type: application/json');

        // Check if the user has permission to access this resource
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, true);
        if ($isAuthorized === false) {
            return false;
        }

        // Get the data sent by the client
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, self::RESOURCES, false);
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
            $changedRows = $statement->rowCount();

            // Check if the update was successful
            if ($changedRows > 0) {
                http_response_code(204);
                return true;
            } else {
                http_response_code(404);
                $details = 'A group with the requested id does not exist.';
                echo new ApiError('group_not_found', $details);
                return false;
            }
        } else {
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function deleteGroup($id) {
        header('Content-Type: application/json');

        // Check if the user has permission to access this resource
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, true);
        if ($isAuthorized === false) {
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
                $details = 'A group with the requested id does not exist.';
                echo new ApiError('group_not_found', $details);
                return false;
            }
        } else {
            http_response_code(500);
            echo new ApiError('database_query_failed');
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
                return new ApiError("invalid_group_name", $details);
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
                return new ApiError("invalid_group_password", $details);
            }
        }

        return null;
    }
}