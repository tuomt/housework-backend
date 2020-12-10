<?php


class GroupMemberController
{
    const TABLE_NAME = "groupmembers";

    static function authenticateGroupMember()
    {
        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, GroupController::AUTHENTICATION_RESOURCES,
            true);

        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Check if group exists and the password is correct
        $group = GroupController::fetchGroup($data["group_name"]);

        if ($group) {
            // Verify password
            if (password_verify($data["group_password"], $group["password"]))
            {
                $groupToken = TokenManager::createGroupToken($group["id"]);
                http_response_code(200);
                echo json_encode(array(
                    "group_id" => $group["id"],
                    "group_token" => $groupToken
                ));
                return true;
            } else {
                // Wrong password
                http_response_code(401);
                echo new ApiError('incorrect_group_password');
                return false;
            }
        } else {
            http_response_code(404);
            $details = 'Group with this name does not exist.';
            echo new ApiError('group_not_found', $details);
            return false;
        }
    }

    static function authorizeGroupMember($groupId, $requireMaster, $authorizedUsers=null, $accessToken=null) {
        /*
         * authorizedUsers must be an array of integers.
         */

        // If access token is not passed to the method, it will be fetched from the authorization header
        if ($accessToken === null) {
            $accessToken = TokenManager::getDecodedAccessToken();
        }

        // Check if token is valid
        if ($accessToken instanceof ApiError) {
            // Send error to client
            http_response_code(401);
            echo $accessToken;
            return false;
        }

        // Get user id from the access token
        $userId = $accessToken->data->user_id;
        // Fetch group member information from database
        $groupMember = self::fetchGroupMember($groupId, $userId, PDO::FETCH_OBJ);

        // Check if the database query failed
        if ($groupMember instanceOf ApiError) {
            http_response_code(500);
            echo $groupMember;
            return false;
        }

        // Check if the user has required rights
        if ($groupMember) {
            if ($authorizedUsers !== null && in_array($userId, $authorizedUsers, true)) {
                return true;
            }

            // Check master privileges
            if ($requireMaster && $groupMember->master === 0) {
                http_response_code(403);
                echo new ApiError('privileges_required');
                return false;
            } else {
                return true;
            }
        } else {
            http_response_code(403);
            $details = "User is not a member of the group.";
            echo new ApiError('permission_denied', $details);
            return false;
        }
    }

    static function authorizeViaGroupToken($token, $groupId) {
        /*
         * Authorize a group member via group token.
         * Checks if the group_id included in the payload of the token matches the groupId argument.
         *
         * Returns true if the authorization is successful.
         * Returns false if the token is invalid or if the group_id in the token does not match
         * the groupId argument. An error is sent to the client if the authorization fails.
         */
        $token = TokenManager::decodeGroupToken($token);

        if ($token instanceOf ApiError) {
            http_response_code(401);
            echo $token;
            return false;
        } else if ($token->data->group_id != $groupId) {
            http_response_code(401);
            $details = 'The group token was not valid for this group.';
            echo new ApiError('invalid_group_token', $details);
            return false;
        } else {
            return true;
        }
    }

    private static function fetchGroupMember($groupId, $userId, $fetchStyle=PDO::FETCH_ASSOC) {
        // Fetch user's group_id and master value from database
        $query = "SELECT * FROM " . self::TABLE_NAME . " WHERE group_id = :group_id and user_id = :user_id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $statement->bindParam(':group_id', $groupId, PDO::PARAM_INT);

        // Execute the statement and fetch user information
        if ($statement->execute()) {
            return $statement->fetch($fetchStyle);
        } else {
            $details = "An error occurred while trying to fetch group member information.";
            return new ApiError('database_query_failed', $details);
        }
    }

    static function getMembers($groupId) {
        // Check if the user has permission to access this resource
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupId, false);
        if ($isAuthorized === false) {
            return false;
        }

        $query = "SELECT u.id, u.name, m.master" .
                " FROM " . self::TABLE_NAME . " as m, " . UserController::TABLE_NAME . " as u" .
                " WHERE m.group_id = :group_id AND m.user_id = u.id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':group_id', $groupId, PDO::PARAM_INT);

        // Execute the statement and fetch all members
        if ($statement->execute()) {
            // Fetch all group members
            $members = $statement->fetchAll(PDO::FETCH_ASSOC);

            // Respond
            if ($members) {
                http_response_code(200);
                echo json_encode($members);
                return true;
            } else {
                http_response_code(404);
                echo new ApiError('group_has_no_members');
                return false;
            }
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }

    static function createMember($groupId) {
        // Get access token
        $accessToken = TokenManager::getDecodedAccessToken();

        // Check if access token is valid
        if ($accessToken instanceOf ApiError) {
            // Invalid token
            http_response_code(401);
            echo $accessToken;
            return false;
        }

        // Get input data from the request
        $data = json_decode(file_get_contents("php://input"), true);

        // Only group token is accepted as input
        $resources = array("group_token" => JsonValidator::T_STRING);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, $resources, true);
        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Check if group-token is valid
        $isAuthorized = self::authorizeViaGroupToken($data["group_token"], $groupId);
        if ($isAuthorized === false) {
            return false;
        }

        // Get user id from the access token
        $userId = $accessToken->data->user_id;

        // Fetch group member information
        $groupMember = self::fetchGroupMember($groupId, $userId, PDO::FETCH_OBJ);

        // Check if the database query failed
        if ($groupMember instanceOf ApiError) {
            http_response_code(500);
            echo $groupMember;
            return false;
        } else if ($groupMember) {
            // The user is already a member of the group
            http_response_code(409);
            echo new ApiError('user_is_already_member');
            return false;
        }

        // Grant master privileges if the user has created the group
        $group = GroupController::fetchGroupById($groupId, PDO::FETCH_OBJ);
        if ($userId == $group->creator_id) {
            $master = 1;
        } else {
            $master = 0;
        }

        $query = "INSERT INTO " . self::TABLE_NAME . " VALUES (:group_id, :user_id, :master)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind params
        $statement->bindParam(':group_id', $groupId, PDO::PARAM_INT);
        $statement->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $statement->bindParam(':master', $master, PDO::PARAM_INT);

        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array("group_id" => (int)$groupId,
                "user_id" => $userId,
                "master" => $master));
            return true;
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError("database_query_failed");
            return false;
        }
    }

    static function deleteMember($groupId, $userId) {
        // Check if the user has permission to access this resource
        $isAuthorized = self::authorizeGroupMember($groupId, true, array((int)$userId));
        if ($isAuthorized === false) {
            return false;
        }

        $query = "DELETE FROM " . self::TABLE_NAME . " WHERE group_id = :group_id AND user_id = :user_id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindValue(':group_id', $groupId, PDO::PARAM_INT);
        $statement->bindValue(':user_id', $userId, PDO::PARAM_INT);

        // Execute the statement and send a response
        if ($statement->execute()) {
            if ($statement->rowCount() > 0) {
                http_response_code(204);
                return true;
            } else {
                http_response_code(404);
                echo new ApiError('group_member_not_found');
                return false;
            }
        } else {
            http_response_code(500);
            echo new ApiError('database_query_failed');
            return false;
        }
    }
}