<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

class ExceptionHandler
{
    static function handle($exception) {
        http_response_code(500);
        if (strcmp($exception->getMessage(), "Uncaught Error") == 0) {
            echo json_encode(array("errormessage" => "Uncaught error in the API."));
        } else {
            echo json_encode(array("errormessage" => "Uncaught exception in the API."));
        }
        error_log($exception->getMessage());
    }

    static function handleError($errno, $errstr, $errfile, $errline) {
        throw new Exception("Uncaught Error #$errno in $errfile at line $errline: $errstr");
    }
}