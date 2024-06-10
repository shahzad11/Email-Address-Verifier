<?php
/**
 * Class EmailVerifier
 * 
 * Handles the verification of email addresses through multiple checks including syntax, domain existence,
 * SMTP server communication, blacklist, SPF, and DKIM records.
 * 
 * Author: Shahzad Ahmad Mirza
 * Author Website: https://shahzadmirza.com
 * 
 * Co-Author: Rizwan
 * Co-Author Website: https://iamrizwan.me
 * 
 */ 

namespace rizwan_47\EmailVerifier;



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
		'smtp_check' => 2,
		// 'blacklist_check' => 4,
		'spf_check' => 1,
		'dkim_check' => 1,
		'tentative_email_deliverability' => 3
	];



	/**
	 * Constructor initializes the EmailVerifier with an email.
	 * 
	 * @param string $email The email address to be verified.
	 */
	public function __construct($email) {

		$this->email = $email;
		$this->domain = substr(strrchr($email, "@"), 1);

		$mxRecords = [];
		getmxrr($this->domain, $mxRecords);

		$this->mxRecords = $mxRecords;

	}



	/**
	 * Performs all checks and calculates a score based on the results of these checks.
	 * 
	 * @return array Contains the results of individual checks, the total score, and details of the email.
	 */
	public function verify() {

		$response = [
			'syntax_check' => $this->syntaxCheck(),
			'domain_check' => $this->domainCheck(),
			'smtp_check' => $this->smtpCheck($this->email),
			'spf_check' => $this->spfCheck(),
			'dkim_check' => $this->dkimCheck(),
			'tentative_email_deliverability' => $this->tentativeEmailDeliverability($this->email)
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
	 * 
	 * @return array|string MX records if available or error message if not.
	 */
	private function getMXRecords() {
		return $this->mxRecords ? $this->mxRecords : "Failed to retrieve MX records for $this->domain";
	}



	/**
	 * Checks the syntax of the email address.
	 * 
	 * @return string 'passed' if syntax is valid, 'failed' otherwise.
	 */
	private function syntaxCheck() {
		return filter_var($this->email, FILTER_VALIDATE_EMAIL) ? 'passed' : 'failed';
	}



	/**
	 * Checks for the existence of MX records for the domain.
	 * 
	 * @return string 'passed' if MX records exist, 'failed' otherwise.
	 */
	private function domainCheck() {
		return checkdnsrr($this->domain, 'MX') ? 'passed' : 'failed';
	}



	/**
	 * Tries to establish an SMTP connection to verify the email address.
	 * 
	 * @param string $email Email address to verify.
	 * @return string 'passed' if the SMTP server verifies the email, 'failed' otherwise.
	 */
	private function smtpCheck($email) {

		// Popular Email SMTP servers that don't need port open checks
		$whitelist = [
			'aspmx.l.google.com'			=> 'Google Workspace (Gmail for Business)',
			'alt1.aspmx.l.google.com'		=> 'Google Workspace (Gmail for Business)',
			'alt2.aspmx.l.google.com'		=> 'Google Workspace (Gmail for Business)',
			'alt3.aspmx.l.google.com'		=> 'Google Workspace (Gmail for Business)',
			'alt4.aspmx.l.google.com'		=> 'Google Workspace (Gmail for Business)',
			'mx1.mailbox.org'				=> 'Mailbox.org',
			'outlook.com'					=> 'Microsoft Outlook',
			'mail.protection.outlook.com'	=> 'Office 365',
			'mx1.smtp.exchangelabs.com'		=> 'Office 365',
			'mx.yandex.net'					=> 'Yandex Mail',
			'mx.zoho.com'					=> 'Zoho Mail',
			'route1.mx.cloudflare.net'		=> 'Cloudways Email Routing',
			'route3.mx.cloudflare.net'		=> 'Cloudways Email Routing',
			'route2.mx.cloudflare.net'		=> 'Cloudways Email Routing'
		];

		$difference = array_diff($this->mxRecords, array_keys($whitelist));

		// All MX records are in the whitelist, we can safely mark this "passed"
		if( empty($difference) )
			return 'passed';

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
	 * 
	 * @param string $mxRecord MX record to test.
	 * @return int|null Port number if successful, null if no suitable port is found.
	 */
	private function detectSmtpPort($mxRecord) {

		$ports = [25, 465, 587, 2525]; // SMTP ports
		$timeout = 1.7; // Reduced timeout to 1.7 seconds

		foreach ($ports as $port) {
			$protocols = ($port === 465) ? ["ssl://"] : ["tcp://"];
			foreach ($protocols as $protocol) {
				$serverAddress = $protocol . $mxRecord . ":" . $port;
				$response = @stream_socket_client($serverAddress, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);

				if ($response) {
					fclose($response);
					return $port;
				}
			}


		}
	
		return null; // No open ports found

	}



	/**
	 * Checks for SPF records for the domain.
	 * 
	 * @return string 'passed' if SPF record exists and is correct, 'failed' otherwise.
	 */
	private function spfCheck() {

		$host = $this->domain;
		$timeout = 1; // Timeout in seconds

		$dnsQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
		$dnsQuery .= implode('', array_map('chr', array_merge(
			array_map('ord', str_split($host)),
			[0, 0, 16, 0, 1]
		)));

		$socket = stream_socket_client("udp://8.8.8.8:53", $errno, $errstr, $timeout);
		if (!$socket) {
			return 'failed';
		}

		fwrite($socket, $dnsQuery);
		stream_set_timeout($socket, $timeout);
		$response = fread($socket, 512);
		fclose($socket);

		if ($response === false) {
			return 'failed';
		}

		$spfRecord = strpos($response, 'v=spf1');
		return $spfRecord !== false ? 'passed' : 'failed';

	}



	/**
	 * Checks for DKIM records for the domain.
	 * 
	 * @return string 'passed' if DKIM record exists and is correct, 'failed' otherwise.
	 */
	private function dkimCheck() {

		$selector = 'default';
		$record = @dns_get_record($selector . '._domainkey.' . $this->domain, DNS_TXT);
		if ($record === false) {
			return 'failed';
		}

		foreach ($record as $entry) {
			if (isset($entry['txt']) && strpos($entry['txt'], 'v=DKIM1') !== false) {
				return 'passed';
			}
		}

		return 'failed';

	}


	/**
	 * Tentative Email Deliverability Check
	 * 
	 * @param string $email Email address to check
	 * 
	 * @return string 'passed' if connection is success, 'failed' otherwise.
	 */
	private function tentativeEmailDeliverability($email) {

		list($user, $domain) = explode('@', $email);
		$mxhosts = [];
		getmxrr($domain, $mxhosts);
		if (count($mxhosts) === 0) return "failed";

		$smtpHost = $mxhosts[0];
		$connection = fsockopen($smtpHost, 25, $errno, $errstr, 1); // 1 second timeout
		if (!$connection) return "failed";

		stream_set_timeout($connection, 1);

		fputs($connection, "HELO emailcheck.com\r\n");
		if (!$response = fgets($connection, 1024)) return "failed";

		fputs($connection, "MAIL FROM: <check@emailcheck.com>\r\n");
		if (!$response = fgets($connection, 1024)) return "failed";

		fputs($connection, "RCPT TO: <$email>\r\n");
		if (!$response = fgets($connection, 1024)) return "failed";

		$isValid = !preg_match("/^5\d\d\s/", $response);
		fclose($connection);

		return $isValid ? "passed" : "failed";
	
	}

}
