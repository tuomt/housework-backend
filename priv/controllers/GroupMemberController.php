<?php


class GroupMemberController
{
    const TABLE_NAME = "groupmembers";

    static function authenticateGroupMember()
    {
        header('Content-Type: application/json');
        $data = json_decode(file_get_contents("php://input"), true);

        // Check if data is valid
        $invalidDataMsg = "";
        $isDataValid = JsonValidator::validateData($data, GroupController::RESOURCES, true, $invalidDataMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $invalidDataMsg"));
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
                http_response_code(401);
                echo json_encode(array("errormessage" => "Wrong password."));
                return false;
            }
        } else {
            http_response_code(401);
            echo json_encode(array("errormessage" => "Group with this name does not exist."));
            return false;
        }
    }

    static function authorizeGroupMember($groupid, $requireMaster, &$outErrorMsg = null) {
        // Check if token is valid
        $token = TokenManager::getDecodedAccessToken($outErrorMsg);
        if ($token === false) {
            return false;
        }
        $userid = $token->data->userid;
        $groups = UserController::fetchAllGroups($userid, PDO::FETCH_OBJ);

        foreach ($groups as $group) {
            // Check if the fetched groupid equals the groupid in the request
            if ($group->groupid == $groupid) {
                // Check if the user has master privileges in case they are required
                if ($requireMaster && $group->master === 0) {
                    $outErrorMsg = "Master privileges required.";
                    return false;
                }
                return true;
            }
        }

        $outErrorMsg = "You are not a member of this group.";
        return false;
    }

    static function authorizeViaGroupToken($token, $groupid, &$outTokenError) {
        $token = TokenManager::decodeGroupToken($token, $outTokenError);
        if (!$token || $token->data->groupid != $groupid) {
            return false;
        } else {
            return true;
        }
    }

    private static function fetchGroupMember($userid) {
        // Fetch user's groupid and master value from database
        $query = "SELECT groupid, master FROM " . self::TABLE_NAME . " WHERE userid = :userid";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        // Execute the statement and fetch user information
        $statement->execute();
        return $statement->fetch(PDO::FETCH_ASSOC);
    }

    static function getMembers($groupid) {
        // TODO: implement
        // GET /api/groups/{groupid}/members
        // Authorize with token
    }

    static function createMember($groupid, $master=0) {
        // POST /api/groups/{groupid}/members with group name + password
        $authenticated = self::authenticateGroupMember();
        if (!$authenticated) {
            return false;
        }

        // Authorize with token, so that you can only create member of yourself
        $tokenVerificationError = "";
        $token = TokenManager::getDecodedAccessToken($tokenVerificationError);
        if (!$token) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $tokenVerificationError"));
            return false;
        }

        // Check that the group exists
        $groupExists = GroupController::fetchGroupById($groupid);
        if ($groupExists === false) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Group with this id does not exist."));
            return false;
        }

        // Fetch all user's groups from the database
        $userid = $token->data->userid;
        $groups = UserController::fetchAllGroups($userid, PDO::FETCH_OBJ);
        if ($groups !== false) {
            foreach($groups as $group) {
                // If user is already in the group, decline request
                if ($group->groupid == $groupid) {
                    http_response_code(400);
                    echo json_encode(array("errormessage" => "User is already a member of this group."));
                    return false;
                }
            }
        }

        $query = "INSERT INTO " . self::TABLE_NAME . " VALUES (:groupid, :userid, :master)";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        $statement->bindParam(':master', $master, PDO::PARAM_INT);
        $statement->execute();

        if ($statement) {
            http_response_code(200);
            echo json_encode(array("message" => "User was added to the group successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to add user to the group."));
            return false;
        }
    }

    static function deleteMember($groupid, $userid) {
        // TODO: implement
        // DELETE /api/groups/{groupid}/members/{userid}
        // Authorize with token, check if is master
    }
}