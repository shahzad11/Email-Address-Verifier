# Email Verifier PHP Library

## Introduction
The EmailVerifier library is designed to facilitate comprehensive email validation checks including syntax, domain verification, SMTP connection testing, SPF and DKIM record validation. This robust tool helps in ensuring that an email address is not only formatted correctly but also valid and active, making it an invaluable resource for developers working on email-related functionalities in PHP.

## About the Author
**Shahzad Ahmad Mirza** is a veteran software developer with extensive experience in PHP development. With a career spanning over two decades, Shahzad has contributed to numerous projects and developed several high-quality software solutions. For more information about Shahzad's work, visit [his personal website](https://shahzadmirza.com) or his company [agency website designsvalley.com](https://designsvalley.com).

## Features

- **Syntax Validation**: Checks if the email address conforms to the standard email formatting rules.
- **Domain Verification**: Verifies if the domain of the email address has MX records indicating a capable mail server.
- **SMTP Checks**: Attempts to establish an SMTP connection to validate the existence and responsiveness of the email address.
- **SPF Check**: Verifies the presence of SPF records, which are essential for preventing email spoofing.
- **DKIM Check**: Checks for DKIM records to ensure the email has not been tampered with and is authorized by the domain owner.


## Installation
To use EmailVerifier in your project, include the EmailVerifier class in your PHP script. No additional libraries or installations are required, making it straightforward to integrate and deploy.

```php
require_once 'path/to/EmailVerifier.php';
```
## Usage
Here is a simple example demonstrating how to use the EmailVerifier library to verify an email address:

```
require_once 'EmailVerifier.php';

$email = 'contact@example.com';
$verifier = new EmailVerifier($email);
$response = $verifier->verify();

echo "<pre>";
print_r($response);
echo "</pre>";
```
This script will output the verification results, including each test's status and a final score indicating the email's validity.


## Example Response
```
Array
(
    [response] => Array
        (
            [syntax_check] => passed
            [domain_check] => passed
            [smtp_check] => passed
            [spf_check] => passed
            [dkim_check] => passed
        )

    [score] => 10
    [email_details] => Array
        (
            [email_address] => contact@gbober.com
            [domain] => gbober.com
            [domain_mx_records] => Array
                (
                    [0] => mail.gbober.com
                )

            [smtp_ports] => Array
                (
                    [0] => 465
                )

        )

)
```

## Response Format

When you call the `verify()` method on an instance of the `EmailVerifier`, it returns an associative array containing detailed results from the verification process. Here's what the response includes:

- **response**: A nested array with the results of individual checks, including:
  - `syntax_check`: Indicates whether the email's syntax is correct (`passed` or `failed`).
  - `domain_check`: Indicates whether the domain has MX records (`passed` or `failed`).
  - `smtp_check`: Indicates whether the SMTP server accepted the email (`passed` or `failed`).
  - `spf_check`: Indicates the presence and correctness of SPF records (`passed` or `failed`).
  - `dkim_check`: Indicates the presence and correctness of DKIM records (`passed` or `failed`).

- **score**: A numerical score representing the cumulative results of the checks. Each check contributes a predefined weight to the score based on its importance and whether it passed.

- **email_details**: Provides additional details about the email and its domain, such as:
  - `email_address`: The email address being verified.
  - `domain`: The domain of the email address.
  - `domain_mx_records`: An array or a string indicating the MX records found or an error message.
  - `smtp_ports`: Lists SMTP ports found open during verification.

Here's an example of how the response might look:

```
Array
(
    [response] => Array
        (
            [syntax_check] => passed
            [domain_check] => passed
            [smtp_check] => failed
            [spf_check] => passed
            [dkim_check] => failed
        )
    [score] => 7
    [email_details] => Array
        (
            [email_address] => contact@example.com
            [domain] => example.com
            [domain_mx_records] => Array
                (
                    [0] => mx1.example.com
                    [1] => mx2.example.com
                )
            [smtp_ports] => Array
                (
                    [0] => 25
                    [1] => 587
                )
        )
)
```

## License
This library is released under the MIT license. See the LICENSE file for more details.
