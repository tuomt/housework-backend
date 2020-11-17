<?php

class TaskController
{
    const TABLE_NAME = "tasks";
    const MIN_NAME_LEN = 3;
    const MAX_NAME_LEN = 42;

    // All resources
    const RESOURCES = array(
        'name' => JsonValidator::T_STRING,
        'startdate' => JsonValidator::T_STRING,
        'enddate' => JsonValidator::T_STRING_NULLABLE,
        'recurring' => JsonValidator::T_INT_NULLABLE,
        'saved' => JsonValidator::T_INT,
        'state' => JsonValidator::T_INT,
        'comment' => JsonValidator::T_STRING
    );

    static function createTask($groupid) {
        header('Content-Type: application/json');
        $errorMsg = "";
        $accessToken = TokenManager::getDecodedAccessToken($errorMsg);
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupid, true, $authError, null, $accessToken);

        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $errorMsg"));
            return false;
        }

        $data = json_decode(file_get_contents("php://input"), true);
        $isDataValid = JsonValidator::validateData($data, self::RESOURCES, true, $errorMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $errorMsg"));
            return false;
        }
        $creatorid = $accessToken->data->userid;

        $query = "INSERT INTO " . self::TABLE_NAME .
            " VALUES (null, :creatorid, :groupid, :name, :startdate, :enddate, :recurring, :saved, :state, :comment)";

        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':creatorid', $creatorid, PDO::PARAM_INT);
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':startdate', $data["startdate"], PDO::PARAM_STR);
        $statement->bindParam(':enddate', $data["enddate"], PDO::PARAM_STR);
        $statement->bindParam(':recurring', $data["recurring"], PDO::PARAM_INT);
        $statement->bindParam(':saved', $data["saved"], PDO::PARAM_INT);
        $statement->bindParam(':state', $data["state"], PDO::PARAM_INT);
        $statement->bindParam(':comment', $data["comment"], PDO::PARAM_STR);

        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array(
                'id' => (int)$conn->lastInsertId(),
                'creatorid' => (int)$creatorid,
                'groupid' => (int)$groupid,
                'name' => $data["name"],
                'starddate' => $data["startdate"],
                'enddate' => $data["enddate"],
                'recurring' => $data["recurring"],
                'saved' => $data["saved"],
                'state' => $data["state"],
                'comment' => $data["comment"]
            ));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to create a task."));
            return false;
        }
    }

    private static function testRequirements(&$data, &$outFailureMsg=null) {
        /*
         * Test if data meets requirements.
         * The data is passed as a reference and may be modified in the following way:
         * - Whitespace is stripped from beginning and end of the string values
         *   before the test.
         *
         * The following conditions are checked:
         * - The string values cannot be empty strings or only consist of whitespace
         * - The value of 'name' must be at least MIN_NAME_LEN characters long
         * - The value of 'name' must be at most MAX_NAME_LEN characters long
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

        return true;
    }
}