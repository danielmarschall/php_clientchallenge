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

	private static function sha3_512($password, $raw_output=false) {
        	if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
	                return hash('sha3-512', $password, $raw_output);
        	} else {
	                return \bb\Sha3\Sha3::hash($password, 512, $raw_output);
        	}
	}

	public static function checkValidation($max_time=10) {

		if (!isset($_REQUEST['vts_validation_result'])) throw new Exception('No challenge response found');

		list($starttime, $ip_target, $challenge, $answer) = @json_decode($_REQUEST['vts_validation_result'], true);

		if ($ip_target != $_SERVER['REMOTE_ADDR']) {
			throw new Exception('Wrong IP');
		} else if (time()-$starttime > $max_time) {
			throw new Exception('Challenge expired');
		} else if ($challenge !== self::sha3_512($starttime.'/'.$ip_target.'/'.$answer)) {
			throw new Exception('Wrong answer');
		} else {
			return true;
		}
	}

	// This is only called by ajax_get_challenge.php
	public static function createChallenge($complexity=500000) {

		$min = 0;
		$max = $complexity;

		$starttime = time();

		$random = rand($min,$max); // TODO: cryptographic rand

		$ip_target = $_SERVER['REMOTE_ADDR'];

		$challenge = self::sha3_512($starttime.'/'.$ip_target.'/'.$random);

		$send_to_client = array($starttime, $ip_target, $challenge, $min, $max);

		header('Content-Type:application/json');
		die(json_encode($send_to_client));

	}

}
