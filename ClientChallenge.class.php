<?php

/*
 * php_clientchallenge
 * Copyright 2021 Daniel Marschall, ViaThinkSoft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace ViaThinkSoft\RateLimitingChallenge;

class ClientChallenge {

	private static function sha3_512($message, $raw_output=false) {
        	if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
	                return hash('sha3-512', $message, $raw_output);
        	} else {
	                return \bb\Sha3\Sha3::hash($message, 512, $raw_output); /** @phpstan-ignore-line */
        	}
	}

	private static function sha3_512_hmac($message, $key, $raw_output=false) {
		// RFC 2104 HMAC
        	if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
	                return hash_hmac('sha3-512', $message, $key, $raw_output);
        	} else {
			$blocksize = 576; // block size of sha-512!

			if (strlen($key) > ($blocksize/8)) {
				$k_ = self::sha3_512($key,true);
			} else {
				$k_ = $key;
			}

			$k_opad = str_repeat(chr(0x5C),($blocksize/8));
			$k_ipad = str_repeat(chr(0x36),($blocksize/8));
			for ($i=0; $i<strlen($k_); $i++) {
				$k_opad[$i] = $k_opad[$i] ^ $k_[$i];
				$k_ipad[$i] = $k_ipad[$i] ^ $k_[$i];
			}

			return self::sha3_512($k_opad . self::sha3_512($k_ipad . $message, true));
        	}
	}

	public static function checkValidation($max_time=10, $server_secret) {

		if (!isset($_REQUEST['vts_validation_result'])) throw new \Exception('No challenge response found');

		list($starttime, $ip_target, $challenge, $answer, $challenge_integrity) = @json_decode($_REQUEST['vts_validation_result'], true);

		if ($ip_target != $_SERVER['REMOTE_ADDR']) {
			throw new \Exception('Wrong IP');
		} else if (time()-$starttime > $max_time) {
			throw new \Exception('Challenge expired');
		} else if ($challenge_integrity != self::sha3_512_hmac($challenge,$server_secret)) {
			throw new \Exception('Challenge integrity failed');
		} else if ($challenge !== self::sha3_512($starttime.'/'.$ip_target.'/'.$answer)) {
			throw new \Exception('Wrong answer');
		} else {
			return true;
		}
	}

	// This is only called by ajax_get_challenge.php
	public static function createChallenge($complexity=500000, $server_secret) {

		$min = 0;
		$max = $complexity;

		$starttime = time();

		$random = rand($min,$max); // TODO: cryptographic rand

		$ip_target = $_SERVER['REMOTE_ADDR'];

		$challenge = self::sha3_512($starttime.'/'.$ip_target.'/'.$random);

		$challenge_integrity = self::sha3_512_hmac($challenge,$server_secret);

		$send_to_client = array($starttime, $ip_target, $challenge, $min, $max, $challenge_integrity);

		header('Content-Type:application/json');
		die(json_encode($send_to_client));

	}

}
