<?php

/*
 * php_clientchallenge
 * Copyright 2021-2022 Daniel Marschall, ViaThinkSoft
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

	const OPEN_TRANS_DIR = __DIR__.'/cache';

	private static function sha3_512($message, $raw_output=false) {
        	if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
	                return hash('sha3-512', $message, $raw_output);
        	} else {
			// Download file if required (usually composer should do it)
			if (file_exists(__DIR__.'/Sha3.php')) include_once __DIR__.'/Sha3.php';
			if (!class_exists('\bb\Sha3\Sha3')) {
				$sha3_lib = file_get_contents('https://raw.githubusercontent.com/danielmarschall/php-sha3/master/src/Sha3.php');
				if (file_put_contents(__DIR__.'/Sha3.php', $sha3_lib)) {
					include_once __DIR__.'/Sha3.php';
				} else {
					eval('?>'.$sha3_lib);
				}
			}
	                return \bb\Sha3\Sha3::hash($message, 512, $raw_output);
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

	private static function getOpenTransFileName($ip_target, $random) {
		// Delete challenges which were never completed
		$files = glob(self::OPEN_TRANS_DIR.'/*.tmp');
		$expire = strtotime('-3 DAYS');
		foreach ($files as $file) {
			if (!is_file($file)) continue;
			if (filemtime($file) > $expire) continue;
			@unlink($file);
		}

		return self::OPEN_TRANS_DIR.'/'.self::sha3_512($ip_target.'/'.$random).'.tmp';
	}

	public static function checkValidation($client_response, $max_time=10, $server_secret) {
		list($starttime, $ip_target, $challenge, $answer, $challenge_integrity) = $client_response;
		$open_trans_file = self::getOpenTransFileName($ip_target, $answer);

		if ($ip_target != $_SERVER['REMOTE_ADDR']) {
			throw new \Exception('Wrong IP');
		} else if (time()-$starttime > $max_time) {
			throw new \Exception('Challenge expired');
		} else if ($challenge_integrity != self::sha3_512_hmac($challenge,$server_secret)) {
			throw new \Exception('Challenge integrity failed');
		} else if ($challenge !== self::sha3_512($starttime.'/'.$ip_target.'/'.$answer)) {
			throw new \Exception('Wrong answer');
		} else if (!file_exists($open_trans_file)) {
			throw new \Exception('Challenge submitted twice or transaction missing');
		} else {
			unlink($open_trans_file);
			return true;
		}
	}

	public static function createChallenge($complexity=50000, $server_secret) {
		$offset = 0; // doesn't matter
		$min = $offset;
		$max = $offset + $complexity;

		$starttime = time();

		$random = rand($min,$max); // TODO: cryptographic rand

		$ip_target = $_SERVER['REMOTE_ADDR'];

		$challenge = self::sha3_512($starttime.'/'.$ip_target.'/'.$random);

		$challenge_integrity = self::sha3_512_hmac($challenge,$server_secret);

		$send_to_client = array($starttime, $ip_target, $challenge, $min, $max, $challenge_integrity);

		$open_trans_file = self::getOpenTransFileName($ip_target, $random);
		if (@file_put_contents($open_trans_file, '') === false) {
			throw new \Exception("Cannot write $open_trans_file");
		}

		return $send_to_client;
	}

}
