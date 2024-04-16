<?php
error_reporting(0);

use rizwan_47\EmailVerifier\EmailVerifier;

// Load dependencies
require __DIR__ . '/vendor/autoload.php';


$email = 'contact@gbober.com';
$verifier = new EmailVerifier($email);
$response = $verifier->verify();

print_r($response);
