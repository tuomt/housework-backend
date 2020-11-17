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

    static function authorizeGroupMember($groupid, $requireMaster, &$outErrorMsg=null, $authorizedUsers=null) {
        // Check if token is valid
        $token = TokenManager::getDecodedAccessToken($outErrorMsg);
        if ($token === false) {
            return false;
        }

        $userid = $token->data->userid;
        // Fetch group member information from database
        $groupMember = self::fetchGroupMember($groupid, $userid, PDO::FETCH_OBJ);

        // Check if the user has required rights
        if ($groupMember) {
            if ($authorizedUsers !== null && in_array($userid, $authorizedUsers, true)) {
                return true;
            }
            // Check master privileges
            if ($requireMaster && $groupMember->master === 0) {
                $outErrorMsg = "Master privileges required.";
                return false;
            } else {
                return true;
            }
        } else {
            $outErrorMsg = "You are not a member of this group or the group doesn't exist.";
            return false;
        }
    }

    static function authorizeViaGroupToken($token, $groupid, &$outTokenError) {
        $token = TokenManager::decodeGroupToken($token, $outTokenError);
        if (!$token || $token->data->groupid != $groupid) {
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
        $statement->execute();
        return $statement->fetch($fetchStyle);
    }

    static function getMembers($groupid) {
        header('Content-Type: application/json');
        // Authorize with token
        $authErrorMsg = "";
        $isAuthorized = GroupMemberController::authorizeGroupMember($groupid, false, $authErrorMsg);
        if (!$isAuthorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authErrorMsg"));
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
        $statement->execute();
        $members = $statement->fetchAll(PDO::FETCH_ASSOC);
        // Respond
        if ($members) {
            http_response_code(200);
            echo json_encode($members);
            return true;
        } else {
            http_response_code(404);
            echo json_encode(array("errormessage" => "This group does not have any members."));
            return false;
        }
    }

    static function createMember($groupid) {
        header('Content-Type: application/json');

        // Check if access-token is valid
        $accessTokenError = "";
        $accessToken = TokenManager::getDecodedAccessToken($accessTokenError);
        if (!$accessToken) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $accessTokenError"));
            return false;
        }

        $data = json_decode(file_get_contents("php://input"), true);
        // Check if data is valid
        $invalidDataMsg = "";
        $resources = array("grouptoken" => JsonValidator::T_STRING);
        $isDataValid = JsonValidator::validateData($data, $resources, true, $invalidDataMsg);
        if (!$isDataValid) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "Received invalid data in the request. $invalidDataMsg"));
            return false;
        }

        // Check if group-token is valid
        $groupTokenError = "";
        $authorized = self::authorizeViaGroupToken($data["grouptoken"], $groupid, $groupTokenError);
        if (!$authorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permisson denied. $groupTokenError"));
            return false;
        }

        $userid = $accessToken->data->userid;
        // Fetch group member information and check if the user is already a member of this group
        $groupMember = self::fetchGroupMember($groupid, $userid, PDO::FETCH_OBJ);
        if ($groupMember) {
            http_response_code(400);
            echo json_encode(array("errormessage" => "User is already a member of this group."));
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
        $statement->bindParam(':groupid', $groupid, PDO::PARAM_INT);
        $statement->bindParam(':userid', $userid, PDO::PARAM_INT);
        $statement->bindParam(':master', $master, PDO::PARAM_INT);
        $statement->execute();

        if ($statement) {
            http_response_code(201);
            echo json_encode(array("message" => "User was added to the group successfully."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to add user to the group."));
            return false;
        }
    }

    static function deleteMember($groupid, $userid) {
        header('Content-Type: application/json');

        // Check if access-token is valid
        $accessTokenError = "";
        $accessToken = TokenManager::getDecodedAccessToken($accessTokenError);
        if (!$accessToken) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $accessTokenError"));
            return false;
        }

        $authError = "";
        $authorized = self::authorizeGroupMember($groupid, $userid, $authError, array($userid));
        if (!$authorized) {
            http_response_code(403);
            echo json_encode(array("errormessage" => "Permission denied. $authError"));
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
        $statement->execute();

        if ($statement->rowCount() > 0) {
            http_response_code(200);
            echo json_encode(array("message" => "Successfully deleted member."));
            return true;
        } else {
            http_response_code(500);
            echo json_encode(array("errormessage" => "Failed to delete member."));
            return false;
        }
    }
}