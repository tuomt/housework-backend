<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

class ExceptionHandler
{
    static function handle($exception) {
        header('Content-Type: application/json');
        http_response_code(500);
        echo new ApiError("unhandled_exception");
        error_log($exception->getMessage());
    }

    static function handleError($errno, $errstr, $errfile, $errline) {
        throw new Exception("Uncaught Error #$errno in $errfile at line $errline: $errstr");
    }
}