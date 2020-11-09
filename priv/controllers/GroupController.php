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
        $authErrorMsg = "";
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, false, $authErrorMsg);
        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authErrorMsg"));
            return false;
        }

        // Build the query
        $query = "SELECT id, name FROM " . self::TABLE_NAME .
                 " WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind id
        $statement->bindParam(':id', $id, PDO::PARAM_INT);
        // Execute the statement
        $statement->execute();
        $group = $statement->fetch(PDO::FETCH_ASSOC);
        // Send a response
        if ($group) {
            http_response_code(200);
            echo json_encode($group);
            return true;
        } else {
            http_response_code(404);
            echo json_encode(array("errormessage" => "Could not find any matches."));
            return false;
        }
    }

    static function createGroup() {
        // TODO: Get userid from token and create a group member of the user (with master privileges)
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
            " VALUES (null, :name, :password)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Create hash from the password
        $passwordHash = password_hash($data["password"], PASSWORD_DEFAULT);
        // Bind params
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':password', $passwordHash, PDO::PARAM_STR);

        // Send a response depending on the outcome of the query
        if ($statement->execute()) {
            // TODO: change this to respond with details of the created group
            http_response_code(201);
            echo json_encode(array("message" => "Group was created successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to create group."));
            return false;
        }

    }

    static function modifyGroup($id) {
        header('Content-Type: application/json');

        // Authorize user
        $authErrorMsg = "";
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, true, $authErrorMsg);
        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authErrorMsg"));
            return false;
        }

        // Get the data sent by the client
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
        $query = "UPDATE " . self::TABLE_NAME .
            " SET name = :name, password = :password 
            WHERE id = :id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Create hash from the password
        $passwordHash = password_hash($data["password"], PASSWORD_DEFAULT);
        // Bind params
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':password', $passwordHash, PDO::PARAM_STR);
        $statement->bindParam(':id', $id, PDO::PARAM_INT);

        // Execute the statement
        $statement->execute();

        // Check if the update was successful and send a response
        $changedRows = $statement->rowCount();
        if ($changedRows > 0) {
            http_response_code(200);
            echo json_encode(array("message" => "Updated group successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to update group."));
            return false;
        }
    }

    static function modifyGroupPartially($id) {
        header('Content-Type: application/json');

        // Authorize user
        $authErrorMsg = "";
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, true, $authErrorMsg);
        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authErrorMsg"));
            return false;
        }

        // Get the data sent by the client
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $invalidDataMsg = "";
        $isDataValid = JsonValidator::validateData($data, self::RESOURCES, false, $invalidDataMsg);
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
            echo json_encode(array("message" => "Updated group successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to update group."));
            return false;
        }
    }

    static function deleteGroup($id) {
        header('Content-Type: application/json');

        // Authorize user
        $authErrorMsg = "";
        $isAuthorized = GroupMemberController::authorizeGroupMember($id, true, $authErrorMsg);
        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authErrorMsg"));
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
            echo json_encode(array("message" => "Successfully deleted group."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to delete group."));
            return false;
        }
    }

    private static function testRequirements(&$data, &$outFailureMsg) {
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

        if (array_key_exists("password", $data)) {
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

        return true;
    }
}