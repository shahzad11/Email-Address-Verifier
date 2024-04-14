<?php

require_once 'EmailVerifier.php';
$email = 'contact@gbober.com';
$verifier = new EmailVerifier($email);
$response = $verifier->verify();
print_r($response);

?>
