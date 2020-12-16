<?php

class TaskController
{
    const TABLE_NAME = "tasks";
    const MIN_NAME_LEN = 3;
    const MAX_NAME_LEN = 42;

    // All resources
    const RESOURCES = array(
        'name' => JsonValidator::T_STRING,
        'start_date' => JsonValidator::T_STRING,
        'end_date' => JsonValidator::T_STRING_NULLABLE,
        'recurring' => JsonValidator::T_INT_NULLABLE,
        'saved' => JsonValidator::T_INT,
        'progress' => JsonValidator::T_INT,
        'description' => JsonValidator::T_STRING_NULLABLE
    );

    static function createTask($groupId) {
        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Check if access token validation failed
        if ($accessToken instanceof ApiError) {
            http_response_code('invalid_access_token');
            // Send error to client
            echo $accessToken;
            return false;
        }

        // Check permissions
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupId, true, null, $accessToken);
        if ($isAuthorized === false) {
            return false;
        }

        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, self::RESOURCES, true);
        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Get user_id from access token
        $creatorId = $accessToken->data->user_id;

        // Build a query
        $query = "INSERT INTO " . self::TABLE_NAME .
            " VALUES (null, :creator_id, :group_id, :name, :start_date, :end_date, :recurring, :saved, :progress, :description)";

        // Connect to database and prepare the query
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':creator_id', $creatorId, PDO::PARAM_INT);
        $statement->bindParam(':group_id', $groupId, PDO::PARAM_INT);
        $statement->bindParam(':name', $data["name"], PDO::PARAM_STR);
        $statement->bindParam(':start_date', $data["start_date"], PDO::PARAM_STR);
        $statement->bindParam(':end_date', $data["end_date"], PDO::PARAM_STR);
        $statement->bindParam(':recurring', $data["recurring"], PDO::PARAM_INT);
        $statement->bindParam(':saved', $data["saved"], PDO::PARAM_INT);
        $statement->bindParam(':progress', $data["progress"], PDO::PARAM_INT);
        $statement->bindParam(':description', $data["description"], PDO::PARAM_STR);

        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array(
                'id' => (int)$conn->lastInsertId(),
                'creator_id' => (int)$creatorId,
                'group_id' => (int)$groupId,
                'name' => $data["name"],
                'start_date' => $data["start_date"],
                'end_date' => $data["end_date"],
                'recurring' => $data["recurring"],
                'saved' => $data["saved"],
                'progress' => $data["progress"],
                'description' => $data["description"]
            ));
            return true;
        } else {
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function getTasks($groupId) {
        // Check permissions
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupId, false);
        if ($isAuthorized === false) {
            return false;
        }

        // Build a query
        $query = "SELECT * FROM " . self::TABLE_NAME . " WHERE group_id = :group_id";

        // Connect to database and prepare the query
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':group_id', $groupId, PDO::PARAM_INT);

        // Execute the query
        if ($statement->execute()) {
            // Fetch all tasks
            $tasks = array();
            $task = $statement->fetch(PDO::FETCH_ASSOC);

            do {
                $doers = TaskDoerController::fetchAllDoers($task["id"]);
                if ($doers) {
                    $task["doers"] = $doers;
                } else {
                    $task["doers"] = null;
                }
                array_push($tasks, $task);
            }
            while ($task = $statement->fetch(PDO::FETCH_ASSOC));

            if (!empty($tasks)) {
                http_response_code(200);
                echo json_encode($tasks);
                return true;
            } else {
                http_response_code(404);
                echo new ApiError('group_has_no_tasks');
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
         * - Whitespace is stripped from beginning and end of the string values
         *   before the test.
         *
         * The following conditions are checked:
         * - The string values cannot be empty strings or only consist of whitespace
         * - The value of 'name' must be at least MIN_NAME_LEN characters long
         * - The value of 'name' must be at most MAX_NAME_LEN characters long
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
                return new ApiError("invalid_task_name", $details);
            }
        }

        return null;
    }
}