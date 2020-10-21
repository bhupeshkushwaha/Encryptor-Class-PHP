# Encryptor-Class-PHP
~~~

<?php

namespace App\Services;


/**
* Class EncryptorService
* @package App\Services
* @author pay2go
*
*/
class EncryptorService {
public static $secretKey = '';

/**
* @param $name
* @param null $selected
* @param array $options
* @return string
*/
function __construct($secret = '')
{
EncryptorService::$secretKey = $secret;

//Encryption Decryption Operations
// $enDecryptionObj = new EncryptorService($mySalt);
// $encryptedValue = EncryptorService::encrypt($realData);
// $decryptedValue = EncryptorService::decrypt($encryptedValue);

//$d = encryptSimple('this is message', 'secret key');
//echo decrypttSimple($d,'secret key');
}

private static function doBase64Encode($string)
{
$data = base64_encode($string);
$data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);

return $data;
}

private static function doBase64Decode($string)
{
$data = str_replace(array('-', '_'), array('+', '/'), $string);
$modBy4 = strlen($data) % 4;
if ($modBy4) {
$data .= substr('====', $modBy4);
}

return base64_decode($data);
}

public static function encrypt($eyValue)
{
if (!$eyValue) {
return false;
}
$text = $eyValue;
$initialVectorSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
$initializeVector = mcrypt_create_iv($initialVectorSize, MCRYPT_RAND);
$encryptText = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, EncryptorService::$secretKey, $text, MCRYPT_MODE_ECB, $initializeVector);

return trim(EncryptorService::doBase64Encode($encryptText));
}

public static function decrypt($dyValue)
{
if (!$dyValue) {
return false;
}
$encryptText = EncryptorService::doBase64Decode($dyValue);
$initialVectorSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
$initializeVector = mcrypt_create_iv($initialVectorSize, MCRYPT_RAND);
$decryptText = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, EncryptorService::$secretKey, $encryptText, MCRYPT_MODE_ECB, $initializeVector);

return trim($decryptText);
}

public static function encryptSimple($data, $secretKey){
$iv = substr(sha1(mt_rand()), 0, 16);

$secretKey = sha1($secretKey);

$salt = sha1(mt_rand());

$saltWithSecretKey = hash_hmac('sha512', $secretKey.$salt, $secretKey);

$encrypted = openssl_encrypt(
"$data", 'aes-256-cbc', "$saltWithSecretKey", null, $iv
);

$string_encrypted_bundle = "$iv:$salt:$encrypted";

return $string_encrypted_bundle;
}


public static function decryptSimple($string_encrypted_bundle, $secretKey){
$secretKey = sha1($secretKey);

$components = explode( ':', $string_encrypted_bundle );

$iv = $components[0];

$salt = hash_hmac('sha512', $secretKey.$components[1], $secretKey);

$encrypted_string = $components[2];
\Log::info(['$encrypted_string', $encrypted_string]);

$decrypted_string = openssl_decrypt(
$encrypted_string, 'aes-256-cbc', $salt, null, $iv
);

\Log::info(['$decrypted_string', $decrypted_string]);

if ( $decrypted_string === false ){
return false;
}

$msg = substr( $decrypted_string, 41 );

return $decrypted_string;
}
}

~~~
