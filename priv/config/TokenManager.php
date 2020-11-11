<?php

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

class TokenManager
{
    const ALGORITHM = 'HS256';
    const AT_EXPIRATION = 900;
    const RT_EXPIRATION = 15778463;
    const GT_EXPIRATION = 900;

    static function createAccessToken($userid) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->accessTokenKey;
        $data = array("userid" => $userid);
        return self::encodeToken($data, self::AT_EXPIRATION, $privateKey);
    }

    static function createRefreshToken($userid) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->refreshTokenKey;
        $data = array("userid" => $userid);
        return self::encodeToken($data, self::RT_EXPIRATION, $privateKey);
    }

    static function createGroupToken($groupid) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->groupTokenKey;
        $data = array("groupid" => $groupid);
        return self::encodeToken($data, self::GT_EXPIRATION, $privateKey);
    }

    private static function encodeToken($data, $expiration, $key) {
        $iat = time(); // The time when token is generated
        $nbf = $iat; // The timestamp when consideration of token starts
        $exp = $iat + $expiration; // Expiration timestamp

        $token = array(
            "iss" => "http://localhost",
            "aud" => "http://localhost",
            "iat" => $iat,
            "nbf" => $nbf,
            "exp" => $exp,
            "data" => $data
        );

        return JWT::encode($token, $key, self::ALGORITHM);
    }

    static function getDecodedAccessToken(&$outErrorMsg=null) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->accessTokenKey;
        return self::decodeTokenFromHeader($privateKey, $outErrorMsg);
    }

    static function getDecodedRefreshToken(&$outErrorMsg=null) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->refreshTokenKey;
        return self::decodeTokenFromHeader($privateKey, $outErrorMsg);
    }

    static function decodeGroupToken($token, &$outErrorMsg=null) {
        $secrets = json_decode(file_get_contents(__DIR__ . '/../secrets/jwt_secrets.json'));
        $privateKey = $secrets->groupTokenKey;
        return self::decodeToken($token, $privateKey, $outErrorMsg);
    }

    private static function decodeTokenFromHeader($key, &$outErrorMsg=null) {
        $token = self::getTokenFromHeaders();
        if ($token === false) {
            $outErrorMsg = "Bearer token was not provided in the authorization header or the format was invalid.";
            return false;
        }
        return self::decodeToken($token, $key, $outErrorMsg);
    }

    private static function decodeToken($token, $key, &$outErrorMsg=null) {
        try {
            $token = JWT::decode($token, $key, array(self::ALGORITHM));
            return $token;
        } catch (ExpiredException $e) {
            $outErrorMsg = "The provided JWT has expired.";
        } catch (BeforeValidException $e) {
            $outErrorMsg = "The provided JWT is not valid yet.";
        } catch (SignatureInvalidException $e) {
            $outErrorMsg = "Could not verify the signature of the provided JWT.";
        } catch (UnexpectedValueException $e) {
            $outErrorMsg = "The provided JWT was invalid.";
        } catch (DomainException $e) {
            $msg = $e->getMessage();
            $outErrorMsg = "The provided JWT was invalid: $msg.";
        }
        return false;
    }

    private static function getTokenFromHeaders() {
        $headers = apache_request_headers();
        // Change every key to uppercase because header field names are case insensitive
        $headers = array_change_key_case($headers, CASE_UPPER);

        foreach ($headers as $header => $value) {
            if ($header === "AUTHORIZATION" && strpos($value, 'Bearer ') === 0) {
                //echo $value, PHP_EOL;
                if (strlen($value) > 7) {
                    $parts = explode(' ', $value, 2);
                    return $parts[1];
                } else return false;
            }
        }
        return false;
    }
}