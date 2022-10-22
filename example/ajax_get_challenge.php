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

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
	require_once __DIR__ . '/../vendor/autoload.php';
}

require_once __DIR__ . '/../ClientChallenge.class.php';

require_once __DIR__ . '/config.inc.php';

try {
	$res = \ViaThinkSoft\RateLimitingChallenge\ClientChallenge::createChallenge(COMPLEXITY, VTS_CS_SERVER_SECRET);
} catch (\Exception $e) {
	$res = array("error" => $e->getMessage());
}

header('Content-Type:application/json');
die(json_encode($res));
