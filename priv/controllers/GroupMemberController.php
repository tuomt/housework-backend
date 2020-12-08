<?php


class GroupMemberController
{
    const TABLE_NAME = "groupmembers";

    static function authenticateGroupMember()
    {
        header('Content-Type: application/json');

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
        $group = GroupController::fetchGroup($data["name"]);

        if ($group) {
            // Verify password
            if (password_verify($data["password"], $group["password"]))
            {
                $groupToken = TokenManager::createGroupToken($group["id"]);
                http_response_code(200);
                echo json_encode(array(
                    "groupid" => $group["id"],
                    "grouptoken" => $groupToken
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

    static function authorizeGroupMember($groupid, $requireMaster, $authorizedUsers=null, $accessToken=null) {
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
        $userid = $accessToken->data->userid;
        // Fetch group member information from database
        $groupMember = self::fetchGroupMember($groupid, $userid, PDO::FETCH_OBJ);

        // Check if the database query failed
        if ($groupMember instanceOf ApiError) {
            http_response_code(500);
            echo $groupMember;
            return false;
        }

        // Check if the user has required rights
        if ($groupMember) {
            if ($authorizedUsers !== null && in_array($userid, $authorizedUsers, true)) {
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

    static function authorizeViaGroupToken($token, $groupid) {
        /*
         * Authorize a group member via group token.
         * Checks if the groupid included in the payload of the token matches the groupid argument.
         *
         * Returns true if the authorization is successful.
         * Returns false if the token is invalid or if the groupid in the token does not match
         * the groupid argument. An error is sent to the client if the authorization fails.
         */
        $token = TokenManager::decodeGroupToken($token);

        if ($token instanceOf ApiError) {
            http_response_code(401);
            echo $token;
            return false;
        } else if ($token->data->groupid != $groupid) {
            http_response_code(401);
            $details = 'The group token was not valid for this group.';
            echo new ApiError('invalid_group_token', $details);
            return false;
        } else {
            return true;
        }
    }

    private static function fetchGroupMember($groupid, $userid, $fetchStyle=PDO::FETCH_ASSOC) {
        // Fetch user's groupid and master value from database
        $query = "SELECT * FROM " . self::TABLE_NAME . " WHERE groupid = :groupid and userid = :userid";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);

        // Execute the statement and fetch user information
        if ($statement->execute()) {
            return $statement->fetch($fetchStyle);
        } else {
            $details = "An error occurred while trying to fetch group member information.";
            return new ApiError('database_query_failed', $details);
        }
    }

    static function getMembers($groupid) {
        header('Content-Type: application/json');

        // Check if the user has permission to access this resource
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupid, false);
        if ($isAuthorized === false) {
            return false;
        }

        $query = "SELECT u.id, u.name, m.master" .
                " FROM " . self::TABLE_NAME . " as m, " . UserController::TABLE_NAME . " as u" .
                " WHERE m.groupid = :groupid AND m.userid = u.id";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);

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

    static function createMember($groupid) {
        header('Content-Type: application/json');

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
        $resources = array("grouptoken" => JsonValidator::T_STRING);

        // Check if data is valid
        $dataError = JsonValidator::validateData($data, $resources, true);
        if ($dataError !== null) {
            http_response_code(400);
            echo $dataError;
            return false;
        }

        // Check if group-token is valid
        $isAuthorized = self::authorizeViaGroupToken($data["grouptoken"], $groupid);
        if ($isAuthorized === false) {
            return false;
        }

        // Get user id from the access token
        $userid = $accessToken->data->userid;

        // Fetch group member information
        $groupMember = self::fetchGroupMember($groupid, $userid, PDO::FETCH_OBJ);

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
        $group = GroupController::fetchGroupById($groupid, PDO::FETCH_OBJ);
        if ($userid == $group->creatorid) {
            $master = 1;
        } else {
            $master = 0;
        }

        $query = "INSERT INTO " . self::TABLE_NAME . " VALUES (:groupid, :userid, :master)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind params
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        $statement->bindParam(':master', $master, PDO::PARAM_INT);

        if ($statement->execute()) {
            http_response_code(201);
            echo json_encode(array("groupid" => (int)$groupid,
                "userid" => $userid,
                "master" => $master));
            return true;
        } else {
            // Query failed
            http_response_code(500);
            echo new ApiError("database_query_failed");
            return false;
        }
    }

    static function deleteMember($groupid, $userid) {
        header('Content-Type: application/json');

        /*
        // Check if access-token is valid
        $accessTokenError = "";
        $accessToken = TokenManager::getDecodedAccessToken($accessTokenError);
        if (!$accessToken) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $accessTokenError"));
            return false;
        }
        */

        // Check if the user has permission to access this resource
        $isAuthorized = self::authorizeGroupMember($groupid, true, array((int)$userid));
        if ($isAuthorized === false) {
            return false;
        }

        $query = "DELETE FROM " . self::TABLE_NAME . " WHERE groupid = :groupid AND userid = :userid";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindValue(':groupid', $groupid, PDO::PARAM_INT);
        $statement->bindValue(':userid', $userid, PDO::PARAM_INT);

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