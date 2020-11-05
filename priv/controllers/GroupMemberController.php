<?php


class GroupMemberController
{
    const TABLE_NAME = "groupmembers";

    static function authorizeGroupMember($groupid, $requireMaster, &$outErrorMsg = null) {
        // Check if token is valid
        $token = TokenManager::getDecodedAccessToken($outErrorMsg);
        if ($token === false) {
            return false;
        }
        $userid = $token->data->userid;
        $groupMember = self::fetchGroupMember($userid);

        // Check if the fetched groupid equals the groupid in the request
        if ($groupMember && $groupMember["groupid"] == $groupid) {
            // Check if the user has master privileges in case they are required
            if ($requireMaster && $groupMember["master"] === 0) {
                $outErrorMsg = "Master privileges required.";
                return false;
            }
            return true;
        } else {
            $outErrorMsg = "You are not a member of this group.";
            return false;
        }
    }

    private static function fetchGroupMember($userid) {
        // Fetch user's groupid and master value from database
        $query = "SELECT groupid, master FROM " . self::TABLE_NAME . " WHERE userid = :userid";

        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        // Bind name
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

    static function createMember($groupid) {
        // TODO: implement
        // POST /api/groups/{groupid}/members with group name + password
        // Authorize with token, so that you can only create member of yourself
        // If is already in the group, decline request
    }

    static function deleteMember($groupid, $userid) {
        // TODO: implement
        // DELETE /api/groups/{groupid}/members/{userid}
        // Authorize with token, check if is master
    }
}