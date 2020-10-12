<?php
set_exception_handler("ExceptionHandler::handle");
set_error_handler("ExceptionHandler::handleError");

class Database
{
    public function getConnection() {
        $secrets = json_decode(file_get_contents(__DIR__ . "/../secrets/db_secrets.json"));

        $dsn = "mysql:host=" . $secrets->hostname . ";dbname=" . $secrets->database . ";charset=utf8";
        $driverOptions = array(
            // Make rowCount() return a value greater than 0 in case
            // a row is not updated because the values are identical
            PDO::MYSQL_ATTR_FOUND_ROWS  => true
        );

        // Create the connection
        $conn = new PDO($dsn, $secrets->username, $secrets->password, $driverOptions);

        // Use real prepared statements
        $conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        // Set error mode
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        return $conn;
    }
}