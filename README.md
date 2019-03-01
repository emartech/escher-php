EscherPHP - HTTP request signing lib [![Build Status](https://travis-ci.org/emartech/escher-php.svg?branch=master)](https://travis-ci.org/emartech/escher-php)
===================================

Escher helps you creating secure HTTP requests (for APIs) by signing HTTP(s) requests. It's both a server side and client side implementation. The status is work in progress.

The algorithm is based on [Amazon's _AWS Signature Version 4_](http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html), but we have generalized and extended it.

More details will be available at our [documentation site](https://documentation.emarsys.com/).


Signing a request
-----------------

Escher works by calculating a cryptographic signature of your request, and adding it (and other authentication information) to said request.
Usually you will want to add the authentication information to the request by appending extra headers to it.
Let's say you want to send a signed POST request to http://example.com/ using the Guzzle\Http library:

```php
<?php

use Escher\Escher;

$method = 'POST';
$url = 'http://example.com';
$requestBody = '{ "this_is": "a_request_body" }';
$yourHeaders = array('Content-Type' => 'application/json');

$headersWithAuthInfo = Escher::create('example/credential/scope')
    ->signRequest('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', $method, $url, $requestBody, $yourHeaders);

$client = new \GuzzleHttp\Client();
$response = $client->post($url, array(
    'body' => $requestBody,
    'headers' => $headersWithAuthInfo
));

```

Presigning an URL
-----------------

In some cases you may want to send authenticated requests from a context where you cannot modify the request headers, e.g. when embedding an API generated iframe.
You can however generate a presigned URL, where the authentication information is added to the query string.

```php
<?php

use Escher\Escher;

$presignedUrl = Escher::create('example/credential/scope')
    ->presignUrl('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', 'http://example.com');

```

Validating a request
--------------------

You can validate a request signed by the methods described above. For that you will need a database of the access keys and secrets of your clients.
Escher accepts any kind of object as a key database that implements the ArrayAccess interface. (It also accepts plain arrays, however it is not recommended to use a php array for a database of API secrets - it's just there to ease testing)

```php
<?php

use Escher\Escher;
use Escher\Exception;

try {
    $keyDB = new \ArrayObject(array(
        'ACCESS_KEY_OF_CLIENT_1'  => 'SECRET OF CLIENT 1',
        'ACCESS_KEY_OF_CLIENT_42' => 'SECRET OF CLIENT 42',
    ));
    Escher::create('example/credential/scope')->authenticate($keyDB);
} catch (Exception $ex) {
    echo 'The validation failed! ' . $ex->getMessage();
}

```

Exceptions
-------------

| Code pattern | Exception type              |
|--------------|-----------------------------|
| 1xxx         | Missing exceptions          |
| 2xxx         | Invalid format exceptions   |
| 3xxx         | Argument invalid exceptions |
| 4xxx         | Not signed exceptions       |
| 5xxx         | Expired exception           |
| 6xxx         | Signature exceptions        |

| Code | Message                                                                             |
|------|-------------------------------------------------------------------------------------|
| 1001 | Escher authentication is missing                                                    |
| 1100 | The {PARAM} header is missing                                                       |
| 1101 | Query key: {PARAM} is missing                                                       |
| 1102 | The host header is missing                                                          |
| 2001 | Date header is invalid, the expected format is Wed, 04 Nov 2015 09:20:22 GMT        |
| 2002 | Auth header format is invalid                                                       |
| 2003 | Invalid {PARAM} query key format                                                    |
| 2004 | Date header is invalid, the expected format is 20151104T092022Z                     |
| 3001 | Invalid Escher key                                                                  |
| 3002 | Hash algorithm is invalid. Only SHA256 and SHA512 are allowed                       |
| 3003 | Credential scope is invalid                                                         |
| 3004 | Date in the authorization header is invalid. It must be the same as the date header |
| 4001 | The host header is not signed                                                       |
| 4002 | The {PARAM} header is not signed                                                    |
| 5001 | The request date is not within the accepted time range                              |
| 6001 | The signatures do not match                                                         |

Debugging
-------------
By sending the  `debug:true` header in the request the 3003, 5001, 6001 errors will contain a base64 encoded debug message.


Configuration
-------------

TBA

Running tests
-------------
1. Install packages with Composer: `composer install`
2. Run tests with `make tests`