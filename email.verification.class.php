<?php

/**
 * Class EmailVerifier
 * Handles the verification of email addresses through multiple checks including syntax, domain existence,
 * SMTP server communication, blacklist, SPF, and DKIM records.
 * Author: Shahzad Ahmad Mirza
 * Author Website: https://shahzadmirza.com
 */
class EmailVerifier {
    private $email;              // Stores the email address to be verified.
    private $domain;             // Extracted domain part of the email address.
    private $smtp_ports = array(); // Detected SMTP ports that are open for communication.
    private $mxRecords;          // Stores MX records of the domain.

    /**
     * Weights assigned to each check during the verification process.
     */
    private $weights = [
        'syntax_check' => 1,
        'domain_check' => 2,
        'smtp_check' => 3,
        'blacklist_check' => 4,
        'spf_check' => 2,
        'dkim_check' => 2,
    ];

    /**
     * Constructor initializes the EmailVerifier with an email.
     * @param string $email The email address to be verified.
     */
    public function __construct($email) {
        $this->email = $email;
        $this->domain = substr(strrchr($email, "@"), 1);
        getmxrr($this->domain, $mxRecords);
        $this->mxRecords = $mxRecords;
    }

    /**
     * Performs all checks and calculates a score based on the results of these checks.
     * @return array Contains the results of individual checks, the total score, and details of the email.
     */
    public function verify() {
        $response = [
            'syntax_check' => $this->syntaxCheck(),
            'domain_check' => $this->domainCheck(),
            'smtp_check' => $this->smtpCheck($this->email),
            'spf_check' => $this->spfCheck(),
            'dkim_check' => $this->dkimCheck(),
        ];

        $score = 0;
        foreach ($response as $check => $result) {
            $score += ($result === 'passed' ? $this->weights[$check] : 0);
        }

        $email_details = [
          'email_address' => $this->email,
          'domain'  => $this->domain,
          'domain_mx_records' => $this->getMXRecords(),
          'smtp_ports' => $this->smtp_ports,
        ];

        return ['response' => $response, 'score' => $score, 'email_details' =>$email_details];
    }

    /**
     * Retrieves the MX records for the domain.
     * @return array|string MX records if available or error message if not.
     */
    private function getMXRecords(){
        if ($this->mxRecords) {
            return $this->mxRecords;
        } else {
            return "Failed to retrieve MX records for $this->domain";
        }
    }

    /**
     * Checks the syntax of the email address.
     * @return string 'passed' if syntax is valid, 'failed' otherwise.
     */
    private function syntaxCheck() {
        return filter_var($this->email, FILTER_VALIDATE_EMAIL) ? 'passed' : 'failed';
    }

    /**
     * Checks for the existence of MX records for the domain.
     * @return string 'passed' if MX records exist, 'failed' otherwise.
     */
    private function domainCheck() {
        return checkdnsrr($this->domain, 'MX') ? 'passed' : 'failed';
    }

    /**
     * Tries to establish an SMTP connection to verify the email address.
     * @param string $email Email address to verify.
     * @return string 'passed' if the SMTP server verifies the email, 'failed' otherwise.
     */
    private function smtpCheck($email) {

      foreach ($this->mxRecords as $mxRecord) {
          $port = $this->detectSmtpPort($mxRecord); // Detect the appropriate SMTP port

          if ($port === null) {
              continue; // If no suitable port is found, skip to the next MX record
          }

          $timeout = 15; // Timeout in seconds
          $context = stream_context_create([
              'ssl' => [
                  'verify_peer' => false,
                  'verify_peer_name' => false,
              ]
          ]);

          // Set protocol based on port
          $protocol = ($port == 465) ? "ssl://" : "tcp://";
          $serverAddress = $protocol . $mxRecord . ":" . $port;

          $response = @stream_socket_client($serverAddress, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, ($port == 465) ? $context : null);
          if (!$response) {
              error_log("Connection failed to $mxRecord on port $port: $errstr ($errno)");
              continue;
          }

          stream_set_timeout($response, $timeout);
          $banner = fgets($response, 4096);
          fwrite($response, "EHLO example.com\r\n");
          $ehloResponse = '';
          while ($str = fgets($response, 4096)) {
              $ehloResponse .= $str;
              if (substr($str, 3, 1) == " ") break; // Stop after the last 250 line
          }

          // If STARTTLS is supported and not already secure, start TLS encryption
          if (strpos($ehloResponse, '250-STARTTLS') !== false && $protocol !== "ssl://") {
              fwrite($response, "STARTTLS\r\n");
              $starttlsResponse = fgets($response, 4096);
              if (strpos($starttlsResponse, '220') === 0) {
                  stream_socket_enable_crypto($response, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                  fwrite($response, "EHLO example.com\r\n"); // Re-send EHLO after STARTTLS
                  $ehloResponse = '';
                  while ($str = fgets($response, 4096)) {
                      $ehloResponse .= $str;
                      if (substr($str, 3, 1) == " ") break;
                  }
              }
          }

          // Send the VRFY command to check the existence of the email
          fwrite($response, "VRFY $email\r\n");
          $vrfyResponse = fgets($response, 4096);
          if (strpos($vrfyResponse, '250') === 0 || strpos($vrfyResponse, '252') === 0) { // 250 or 252 positive completion reply
              fclose($response);
              return 'passed';
          }

          fclose($response);
      }

      return 'failed';
    }

    /**
     * Detects the SMTP port to communicate with the server.
     * @param string $mxRecord MX record to test.
     * @return int|null Port number if successful, null if no suitable port is found.
     */
    private function detectSmtpPort($mxRecord) {
      $ports = [25, 587, 465]; // Ports to check
      $timeout = 10; // Timeout in seconds

      foreach ($ports as $port) {
          $context = stream_context_create([
              'ssl' => [
                  'verify_peer' => false,
                  'verify_peer_name' => false,
              ]
          ]);

          // Try both non-encrypted and SSL/TLS contexts
          foreach ([null, $context] as $contextOption) {
              $protocol = ($contextOption === $context) ? "ssl://" : "tcp://";
              $serverAddress = $protocol . $mxRecord . ":" . $port;

              $response = @stream_socket_client($serverAddress, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $contextOption);
              if ($response) {
                  stream_set_timeout($response, $timeout);
                  $banner = fgets($response, 1024);

                  // Send EHLO command to check for STARTTLS support
                  fwrite($response, "EHLO detectport\r\n");
                  $ehloResponse = '';
                  while ($str = fgets($response, 1024)) {
                      $ehloResponse .= $str;
                      if (substr($str, 3, 1) == " ") break; // Read until the last response line
                  }

                  // Check if the server response indicates STARTTLS or if it's an encrypted connection
                  if (strpos($ehloResponse, '250-STARTTLS') !== false || $protocol === "ssl://") {
                      fclose($response);
                      $this->smtp_ports[] = $port;
                      return $port; // Return the port if STARTTLS is available or connection is already secure
                  }

                  fclose($response);
              }
          }
      }

      return null; // No suitable port found
    }

    /**
     * Checks for SPF records for the domain.
     * @return string 'passed' if SPF record exists and is correct, 'failed' otherwise.
     */
    private function spfCheck() {
      $record = dns_get_record($this->domain, DNS_TXT);
      foreach ($record as $entry) {
          if (strpos($entry['txt'], 'v=spf1') === 0) {
              return 'passed';
          }
      }
      return 'failed';
    }

    /**
     * Checks for DKIM records for the domain.
     * @return string 'passed' if DKIM record exists and is correct, 'failed' otherwise.
     */
    private function dkimCheck() {
      $selector = 'default'; // Change this to the actual selector used by the domain
      $record = dns_get_record($selector . '._domainkey.' . $this->domain, DNS_TXT);
      foreach ($record as $entry) {
          if (strpos($entry['txt'], 'v=DKIM1') !== false) {
              return 'passed';
          }
      }
      return 'failed';
    }
}





?>
