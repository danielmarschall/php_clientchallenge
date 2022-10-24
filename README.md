

# Server requests using client challenges

### What is it?
This PHP/JavaScript package can be used to add client challenges on top of your
AJAX requests to protect your scripts against brute-force or DoS attacks.
It can also protect your server against resource starvation attacks, for example,
if you have a login script that uses a complex hash algorithm like BCrypt.

### Usage example
A usage example is located in the directory example/

### System requirements
- PHP-compatible web server (tested with Apache 2, nginx, and Microsoft IIS)
- PHP 7.0 or higher (also tested with PHP 8.0)
- Independent of operating system (tested with Windows, Linux, and macOS X)


### Program flow

#### 1. Request from Client to Server (Get Challenge)
Request parameters:
- None

The server will generate a secret random number between Min and Max.
The difference between Min and Max is the complexity constant.

Response:
- Current time ("Start time")
- IP address of the client
- Challenge = `Hash(StartTime + IP address + Random number)`
- Min value
- Max value
- Challenge integrity = `Hash_HMAC(Challenge, ServerSecret)`

Additionally, the server will create a "transaction file" (which prevents a replay attack). The filename is `Hash_HMAC(IP+Random, ServerSecret)`.

The client will now brute-force all values to find the random value between Min and Max.

#### 2. Request from Client to Server (Solve Challenge and request the resource)

Request parameters:
- StartTime (as received previously from the server)
- IP address of the client (as received previously from the server)
- Challenge (as received previously from server)
- Answer (the random number found)
- Challenge Integrity (as received previously from the server)

The server will do:
- Check if parameters exist and have the correct data type 
- Verify that the IP address is the same, otherwise return the error "IP address changed"
- Verify StartTime is not older than "X" minutes*, otherwise return the error "Challenge expired"
- Verify that the challenge integrity fits the HMAC of the Challenge
- Check if the challenge was solved, i.e. Original Challenge matches `Hash(StartTime + IP + Answer)`
- Check if the transaction file exists, otherwise return the error "Challenge submitted twice"
- If all is OK, delete the transaction file (to prevent the answer is sent again) and grant access to the resource

Note: Depending on when you solve the challenge, you should decide on a fitting timeout value, e.g.
- When the challenge is solved once the login/contact/... form is shown -> choose a timeout value of 10 minutes. The usage of a "transaction file" is important, because the same challenge can be submitted within 10 minutes.
- When the challenge is solved during the pressing of the "log in/send/..." button -> choose a timeout value of 10-30 seconds (depending on what your complexity constant is and how fast the client CPU is). Usage of "transaction file" is still recommended, but not as important.

### Reporting a bug
You can file a bug report here:
- https://www.viathinksoft.com/thinkbug/thinkbug.php?id=119
- https://www.viathinksoft.com/contact/daniel-marschall
- https://github.com/danielmarschall/php_clientchallenge/issues

### Support
If you have any questions or need help, please contact us:
https://www.viathinksoft.com/contact/daniel-marschall
