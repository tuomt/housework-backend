<?php


class TaskDoerController
{
    const TABLE_NAME = "taskdoers";

    static public function fetchAllDoers($taskId, $fetchStyle=PDO::FETCH_ASSOC) {
        $query = "SELECT d.user_id, u.name "
            . "FROM " . self::TABLE_NAME . " as d, "
            . UserController::TABLE_NAME . " as u "
            . "WHERE d.user_id = u.id "
            . "AND task_id = :task_id";
        // Connect to database
        $db = new Database();
        $conn = $db->getConnection();
        $statement = $conn->prepare($query);
        $statement->bindParam(':task_id', $taskId, PDO::PARAM_INT);
        // Execute the statement and fetch user information
        $statement->execute();
        return $statement->fetchAll($fetchStyle);
    }
}