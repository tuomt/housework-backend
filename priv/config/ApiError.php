<?php


class ApiError
{
    private $type = null;
    private $message = null;
    private $details = null;

    public function __construct($type, $details=null) {
        $error = $this->fetchError($type);
        if ($error === null) {
            throw new Exception("Could not find an error with type '$type'");
        }
        $this->type = $error["type"];
        $this->message = $error["message"];
        if ($details === null) {
            $this->details = $error["details"];
        } else {
            $this->details = $details;
        }
    }

    public function __toString() {
        return $this->toJson();
    }

    public function toArray() {
        return array("type" => $this->type,
            "message" => $this->message,
            "details" => $this->details);
    }

    public function toJson() {
        return json_encode($this->toArray());
    }

    private static function fetchError($type) {
        $file = __DIR__ . "/../../public/errors.json";
        $errors = json_decode(file_get_contents($file), true);

        foreach ($errors as $error) {
            if ($error["type"] === $type) {
                return $error;
            }
        }
        return null;
    }
}