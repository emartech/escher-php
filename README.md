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

    $method = 'POST';
    $url = 'http://example.com';
    $requestBody = '{ "this_is": "a_request_body" }';
    $yourHeaders = array('Content-Type' => 'application/json');

    $headersWithAuthInfo = Escher::create('example/credential/scope')
        ->signRequest('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', $method, $url, $requestBody, $yourHeaders);

    $client = new GuzzleHttp\Client();
    $response = $client->post($url, array(
        'body' => $requestBody,
        'headers' => $headersWithAuthInfo
    ));

Presigning an URL
-----------------

In some cases you may want to send authenticated requests from a context where you cannot modify the request headers, e.g. when embedding an API generated iframe.
You can however generate a presigned URL, where the authentication information is added to the query string.

    $presignedUrl = Escher::create('example/credential/scope')
        ->presignUrl('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', 'http://example.com');


Validating a request
--------------------

You can validate a request signed by the methods described above. For that you will need a database of the access keys and secrets of your clients.
Escher accepts any kind of object as a key database that implements the ArrayAccess interface. (It also accepts plain arrays, however it is not recommended to use a php array for a database of API secrets - it's just there to ease testing)

    try {
        $keyDB = new ArrayObject(array(
            'ACCESS_KEY_OF_CLIENT_1'  => 'SECRET OF CLIENT 1',
            'ACCESS_KEY_OF_CLIENT_42' => 'SECRET OF CLIENT 42',
        ));
        Escher::create('example/credential/scope')->validateRequest($keyDB);
    } catch (EscherException $ex) {
        echo 'The validation failed! ' . $ex->getMessage();
    }

Configuration
-------------

TBA
