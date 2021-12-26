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

function vts_validated_call(getChallengeScript, callback, params, error_cb) {
	$.ajax({
		type: "POST",
		url: getChallengeScript,
		data: {
		},
		success: function(data) {
			var starttime = data[0];
			var ip_target = data[1];
			var challenge = data[2];
			var min = data[3];
			var max = data[4];
			var challenge_integrity = data[5];
			for (i=min; i<=max; i++) {
				if (challenge == sha3_512(starttime+"/"+ip_target+"/"+i)) {
					var answer = i;
					var vts_validation_result = JSON.stringify([starttime, ip_target, challenge, answer, challenge_integrity]);
					callback(params, vts_validation_result);
					break;
				}
			}
		},
		error: error_cb
	});
}
