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

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
	require_once __DIR__ . '/../vendor/autoload.php';
}

require_once __DIR__ . '/../ClientChallenge.class.php';

require_once __DIR__ . '/config.inc.php';

if (isset($_REQUEST['action']) && ($_REQUEST['action'] === 'add_numbers')) {

	// Check request field "vts_validation_result" for valid response of the Challenge
	try {
		\ViaThinkSoft\RateLimitingChallenge\ClientChallenge::checkValidation(MAX_TIME, VTS_CS_SERVER_SECRET);
	} catch (\Exception $e) {
		$res = array("error" => $e->getMessage());
		header('Content-Type:application/json');
		die(json_encode($res));
	}

	// Do your stuff here. Example:
	$a = $_REQUEST['a'];
	$b = $_REQUEST['b'];

	$res = array("result" => ($a+$b));

	header('Content-Type:application/json');
	die(json_encode($res));
}
