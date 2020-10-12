<?php


class JsonValidator
{
    // Data type constants
    const T_INT = 0;
    const T_STRING = 1;
    const T_BOOL = 2;
    const T_INT_NULLABLE = 100;
    const T_STRING_NULLABLE = 101;
    const T_BOOL_NULLABLE = 102;

    public static function validateData($data, $resources, $requireAllResources=false, &$outErrorMsg=null)
    {
        /*
         * Validates JSON data.
         * The data must be an array of JSON key => value pairs.
         *
         * resources should be an array that contains modifiable resource names
         * as key => value pairs. A key in the array should contain name of the resource.
         * A value in the array should contain one of the data type constants defined in
         * this class. The constant should be chosen based on the expected value of the resource,
         * e.g. for an int variable the corresponding type is 'JsonValidator::T_INT'.
         * Nullable types, for example the 'JsonValidator::T_STRING_NULLABLE', can be used to
         * accept null values.
         *
         * Example of a resources array:
         *
         * const RESOURCES = array(
         *     'id' => "JsonValidator::T_INT",
         *     'name' => "JsonValidator::T_STRING",
         *     'age' => "JsonValidator::T_INT_NULLABLE",
         *     'email' => "JsonValidator::T_STRING_NULLABLE",
         *     'haslicense' => "JsonValidator::T_BOOL"
         * );
         *
         * If the requireAllResources argument is set to true (default: false),
         * the function will return false in case the data does not contain all
         * of the keys defined in the resources array.
         *
         * Optional argument outErrorMsg will be set to an appropriate error message
         * in case any validation condition is not fulfilled or the validation fails.
        */

        if (empty($data) || !is_array($data)) {
            $outErrorMsg = "Invalid format.";
            return false;
        }

        if ($requireAllResources) {
            $keyDifference = array_diff_key($resources, $data);
            if (!empty($keyDifference)) {
                    $outErrorMsg = "The following keys are missing: ";
                    $count = count($keyDifference);
                    $i = 1;
                    foreach ($keyDifference as $key => $value) {
                        $outErrorMsg .= "'$key'";
                        if ($i < $count) $outErrorMsg .= ", ";
                        $i++;
                    }
                    return false;
                }
        }

        // Validate each key and each value one by one
        foreach ($data as $key => $value) {
            if (!self::validateKeyValue($key, $value, $resources, $outErrorMsg)) return false;
        }
        return true;
    }

    public static function validateKeyValue($key, $value, $resources, &$outErrorMsg=null)
    {
        /*
         * Validates a JSON key => value pair.
         * The key should contain a name of a resource that will be modified, e.g. 'username'.
         * The value should contain a value that will be set to the resource.
         *
         * resources should be an array that contains modifiable resource names
         * as key => value pairs. A key in the array should contain name of the resource.
         * A value in the array should contain one of the data type constants defined in
         * this class. The constant should be chosen based on the expected value of the resource,
         * e.g. for an int variable the corresponding type is 'JsonValidator::T_INT'.
         * Nullable types, for example 'JsonValidator::T_STRING_NULLABLE', can be used to accept
         * null values.
         *
         * Example of a resources array:
         *
         * const RESOURCES = array(
         *     'id' => "JsonValidator::T_INT",
         *     'name' => "JsonValidator::T_STRING",
         *     'age' => "JsonValidator::T_INT_NULLABLE",
         *     'email' => "JsonValidator::T_STRING_NULLABLE",
         *     'haslicense' => "JsonValidator::T_BOOL"
         * );
         *
         * Optional argument outErrorMsg will be set to an appropriate error message
         * in case any validation condition is not fulfilled or the validation fails.
         *
         * Returns false if the key is not a modifiable resource, if the value is of wrong
         * data type or the validation fails.
         * Returns true if the key is a modifiable resource and the value is valid.
         */

        if (!array_key_exists($key, $resources)) {
            $outErrorMsg = "The key '$key' is not a modifiable resource.";
            return false;
        } else {
            $resourceType = $resources[$key];
            $validType = self::validateResourceType($resourceType, $value);

            if ($validType === true) {
                return true;
            } else if ($validType === false) {
                $outErrorMsg = "Failed to validate key '$key', invalid resource type.";
                return false;
            } else {
                $outErrorMsg = "The value for the key '$key' should be of type $validType.";
                return false;
            }
        }
    }

    public static function validateStringLength($strValue, $min, $max, $key=null, &$outErrorMsg=null) {
        $len = strlen($strValue);
        if ($len < $min) {
            if ($key !== null) {
                $outErrorMsg = "The value of '$key' is too short. The value must be at least $min characters long.";
            }
            return false;
        } else if ($len > $max) {
            if ($key !== null) {
                $outErrorMsg = "The value of '$key' is too long. The value must be at most $max characters long.";
            }
            return false;
        } else return true;
    }

    private static function validateResourceType($resourceType, $value) {
        // Check if the value is of correct data type
        $validType = true;
        switch ($resourceType) {
            default:
                return false;
            case self::T_INT:
                if (!is_int($value)) {
                    $validType = "int";
                }
                break;
            case self::T_STRING:
                if (!is_string($value)) {
                    $validType = "string";
                }
                break;
            case self::T_BOOL:
                if (!is_bool($value)) {
                    $validType = "bool";
                }
                break;
            case self::T_INT_NULLABLE:
                if (!is_null($value) && !is_int($value)) {
                    $validType = "int or null";
                }
                break;
            case self::T_STRING_NULLABLE:
                if (!is_null($value) && !is_string($value)) {
                    $validType = "string or null";
                }
                break;
            case self::T_BOOL_NULLABLE:
                if (!is_null($value) && !is_bool($value)) {
                    $validType = "bool or null";
                }
                break;
        }
        return $validType;
    }
}