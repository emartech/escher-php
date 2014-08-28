<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $example = AsrExample::getDefault();
        $headersToSign =  array('content-type', 'host', 'x-ems-date');
        $headerList = $example->defaultHeaders();
        $this->assertEqualMaps($example->allHeaders(), $this->callSignRequest($example, $headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $headerList = $example->contentTypeHeader();
        $this->assertEqualMaps($example->allHeaders(), $this->callSignRequest($example, $headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostToSignedHeaders()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type');
        $headerList = $example->contentTypeHeader();
        $this->assertEqualMaps($example->allHeaders(), $this->callSignRequest($example, $headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $extra = array('x-a-header' => 'that/should/not/be/signed');
        $contentType = $example->contentTypeHeader();

        $expected = $example->allHeaders() + $extra;
        $this->assertEqualMaps($expected, $this->callSignRequest($example, $contentType + $extra, $headersToSign));
    }

    public function callSignRequest(AsrExample $example, $headerList, $headersToSign)
    {
        return $example->createClient()->getSignedHeaders(
            'POST',
            $example->url(),
            $example->requestBody,
            $headerList,
            $headersToSign,
            $example->defaultDateTime(),
            'Authorization'
        );
    }

    /**
     * @test
     */
    public function itShouldUseTheServersRequestTimeAsTheFullDate()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type','host','x-ems-date');
        $_SERVER['REQUEST_TIME'] = $example->getTimeStamp();
        $actual = $example->createClient()->getSignedHeaders(
            $example->method,
            $example->url(),
            $example->requestBody,
            $example->defaultHeaders(),
            $headersToSign,
            $example->defaultDateTime(),
            'Authorization'
        );
        $expected = $example->allHeaders();
        $this->assertEqualMaps($expected, $actual);
    }

    /**
     * @test
     */
    public function itShouldUseTheProvidedAuthHeaderName()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type');
        $_SERVER['REQUEST_TIME'] = $example->getTimeStamp();
        $actual = $example->createClient()->getSignedHeaders(
            $example->method,
            $example->url(),
            $example->requestBody,
            $example->defaultHeaders(),
            $headersToSign,
            $example->defaultDateTime(),
            'CustomHeader'
        );
        $expected = $example->allHeaders('CustomHeader');
        $this->assertEqualMaps($expected, $actual);
    }

    /**
     * @test
     * @dataProvider headerNames
     */
    public function itShouldParseAuthorizationHeader($authHeaderName, $dateHeaderName)
    {
        $example = AsrExample::getDefault();
        $authHeader = AsrAuthElements::parseFromHeaders(
            $example->authorizationHeader($authHeaderName) + $example->dateHeader($dateHeaderName) + $example->hostHeader(),
            $authHeaderName,
            $dateHeaderName,
            'EMS'
        );

        $this->assertEquals($example->date, $authHeader->getLongDate());
        $this->assertEquals($example->accessKeyId, $authHeader->getAccessKeyId());
        $this->assertEquals($example->shortDate(), $authHeader->getShortDate());
        $this->assertEquals($example->region, $authHeader->getRegion());
        $this->assertEquals($example->service, $authHeader->getService());
        $this->assertEquals($example->requestType, $authHeader->getRequestType());
        $this->assertEquals($example->headerKeys(), $authHeader->getSignedHeaders());
        $this->assertEquals($example->signature, $authHeader->getSignature());
    }

    public function headerNames()
    {
        return array(
            'default'       => array('authorization', 'date'),
            'upcase'        => array('Authorization', 'Date'),
            'custom'        => array('x-ems-auth',    'x-ems-date'),
            'custom upcase' => array('X-Ems-Auth',    'X-Ems-Date'),
        );
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $actualSigningKey = AsrSigner::calculateSigningKey(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20110909/us-east-1/iam/aws4_request",
            'sha256',
            'AWS4'
        );

        $this->assertEquals(
            "98f1d889fec4f4421adc522bab0ce1f82e6929c262ed15e5a94c90efd1e3b0e7",
            bin2hex($actualSigningKey)
        );
    }

    /**
     * @test
     */
    public function itShouldGenerateSignedHeaders()
    {
        $example = AsrExample::getCustom();
        $client = $example->createClient();

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $signedHeaders = $client->getSignedHeaders(
            $example->method,
            "http://example.com/something",
            "",
            array('Some-Custom-Header' => 'FooBar'),
            array(),
            $date,
            'x-ems-auth'
        );

        $expectedSignedHeaders = array('some-custom-header' => 'FooBar') + $example->dateHeader() + $example->authorizationHeader('x-ems-auth') + $example->hostHeader();

        $this->assertEqualMaps($expectedSignedHeaders, $signedHeaders);
    }

    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $example = AsrExample::getCustom();
        $client = $example->createClient();

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $expires = 123456;
        $signedUrl = $client->getSignedUrl('http://example.com/something?foo=bar&baz=barbaz', $date, $expires);

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&' . $example->signedQueryParams;

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddMandatoryHeaders()
    {
        $example = AsrExample::getCustom();
        $client = $example->createClient();

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $expires = 123456;
        $signedUrl = $client->getSignedUrl('http://example.com/something?foo=bar&baz=barbaz', $date, $expires, array(), array());

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&' . $example->signedQueryParams;

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldParseHeaders()
    {
        $example = AsrExample::getDefault();
        $serverVars = array(
            'REQUEST_TIME' => time(),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => $example->host,
            'CONTENT_TYPE' => $example->contentType,
            'REQUEST_URI' => '/path?query=string'
        );
        $requestBody = 'BODY';
        $helper = $this->createRequestHelper($serverVars, $requestBody);
        $this->assertEquals($requestBody, $helper->getRequestBody());
        $this->assertEqualMaps($example->contentTypeHeader() + $example->hostHeader(), $helper->getHeaderList());
    }

    protected function createRequestHelper($serverVars, $requestBody)
    {
        return new AsrRequestHelper($serverVars, $requestBody, 'Authorization', 'X-Ems-Date');
    }

    /**
     * @test
     */
    public function itShouldValidateRequestUsingAuthHeader()
    {
        $example = AsrExample::getDefault();
        $serverVars = $this->goodServerVarsWithAuthHeaders($example);
        $example->createServer()->validateRequest($serverVars, $example->requestBody);
    }

    /**
     * @test
     * @dataProvider requestTamperingProvider
     */
    public function itShouldFailForInvalidAuthHeader($tamperedKey, $tamperedValue, $expectedErrorMessage)
    {
        $example = AsrExample::getDefault();
        $serverVars = $this->goodServerVarsWithAuthHeaders($example);
        $serverVars[$tamperedKey] = $tamperedValue;
        $asrServer = $example->createServer();
        try {
            $asrServer->validateRequest($serverVars, $example->requestBody);
            $this->fail('Should fail to validate');
        } catch (AsrException $ex) {
            $this->assertEquals($expectedErrorMessage, $ex->getMessage());
        }
    }

    /**
     * @test
     * @expectedException AsrException
     * @expectedExceptionMessage Date header not signed
     */
    public function itShouldValidateAgainstProvidedHeaderNames()
    {
        $example = AsrExample::getDefault();
        $serverVars = $this->goodServerVarsWithCustomAuthHeaders($example);
        $example->createServer()->validateRequest($serverVars, $example->requestBody, 'Custom-Auth', 'Custom-Date');
    }

    private function goodServerVarsWithAuthHeaders(AsrExample $example)
    {
        return array(
            'HTTP_X_EMS_DATE' => $example->date,
            'HTTP_X_EMS_AUTH' => $example->authorizationHeaderValue(),
        ) + $this->goodServerVars($example);
    }

    private function goodServerVarsWithCustomAuthHeaders(AsrExample $example)
    {
        return array(
            'HTTP_CUSTOM_DATE' => $example->date,
            'HTTP_CUSTOM_AUTH' => $example->authorizationHeaderValue(),
        ) + $this->goodServerVars($example);
    }

    private function goodServerVars(AsrExample $example)
    {
        return array(
            'REQUEST_TIME' => $example->getTimeStamp() + rand(0, 100),
            'REQUEST_METHOD' => $example->method,
            'HTTP_HOST' => $example->host,
            'CONTENT_TYPE' => $example->contentType,
            'REQUEST_URI' => $example->requestUri,
            'HTTPS' => null,
            'SERVER_PORT' => '80',
            'SERVER_NAME' => $example->host,
        );
    }

    public function requestTamperingProvider()
    {
        $example = AsrExample::getDefault();
        return array(
            'wrong date'            => array('HTTP_X_EMS_DATE', $example->tamperDate(), 'Invalid request date.'),
            'wrong auth header'     => array('HTTP_X_EMS_AUTH', 'Malformed', 'Could not parse authorization header.'),
            'tampered signature'    => array('HTTP_X_EMS_AUTH', $example->tamperSignature(), 'The signatures do not match'),
            'wrong hash algo'       => array('HTTP_X_EMS_AUTH', $example->tamperHashAlgo(), 'Only SHA256 and SHA512 hash algorithms are allowed.'),
            'host not signed'       => array('HTTP_X_EMS_AUTH', $example->unsignHost(), 'Host header not signed'),
            'date not signed'       => array('HTTP_X_EMS_AUTH', $example->unsignDate(), 'Date header not signed'),
            'wrong request time'    => array('REQUEST_TIME', $example->tamperDate(), 'Request date is not within the accepted time interval.'),
            'wrong host'            => array('HTTP_HOST', 'example.com', 'The host header does not match.'),
        );
    }

    /**
     * @test
     */
    public function itShouldValidateRequestUsingQueryString()
    {
        $example = AsrExample::getCustom();
        $serverVars = $this->goodServerVars($example);
        $example->createServer()->validateRequest($serverVars, $example->requestBody);
    }

    /**
     * @test
     * @expectedException AsrException
     */
    public function itShouldValidateNoQueryParamModifiedInRequestUsingQueryString()
    {
        $example = AsrExample::getCustom();
        $serverVars = $this->goodServerVars($example);
        $serverVars['REQUEST_URI'] = str_replace('123456', '86400', $serverVars['REQUEST_URI']);
        $example->createServer()->validateRequest($serverVars, $example->requestBody);
    }

    /**
     * @test
     */
    public function calculateSigningKey_Perfect_Perfect()
    {
        $actualSigningKey = AsrSigner::calculateSigningKey(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20110909/us-east-1/iam/aws4_request",
            'sha256',
            'AWS4'
        );

        $this->assertEquals(
            "98f1d889fec4f4421adc522bab0ce1f82e6929c262ed15e5a94c90efd1e3b0e7",
            bin2hex($actualSigningKey)
        );
    }

    private function assertEqualMaps(array $expected, array $actual, $message = '')
    {
        ksort($expected);
        ksort($actual);
        $this->assertEquals($expected, $actual, $message);
    }
}

class AsrExample
{
    public $date;
    public $secretKey;
    public $accessKeyId;
    public $region;
    public $service;
    public $requestType;
    public $host;
    public $contentType;
    public $requestBody;
    public $headers;
    public $signature;
    public $method;
    public $authHeaderValue;
    public $signedQueryParams;
    public $requestUri;

    /**
     * @return AsrExample
     */
    public static function getDefault()
    {
        $result = new AsrExample();
        $result->date = '20110909T233600Z';
        $result->secretKey = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $result->accessKeyId = 'AKIDEXAMPLE';
        $result->region = 'us-east-1';
        $result->service = 'iam';
        $result->requestType = 'aws4_request';
        $result->host = 'iam.amazonaws.com';
        $result->contentType = 'application/x-www-form-urlencoded; charset=utf-8';
        $result->requestBody = 'Action=ListUsers&Version=2010-05-08';
        $result->signature = 'f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd';
        $result->method = 'POST';
        $result->headers = array(
            'content-type' => $result->contentType,
            'host' => $result->host,
            'x-ems-date' => $result->date,
        );
        $result->authHeaderValue = 'EMS-HMAC-SHA256 '.
            'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
            'SignedHeaders=content-type;host;x-ems-date, '.
            'Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd';
        $result->signedQueryParams = '';
        $result->requestUri = '/';
        return $result;
    }

    public static function getCustom()
    {
        $result = self::getDefault();
        $result->accessKeyId = "th3K3y";
        $result->secretKey = "very_secure";
        $result->method = 'GET';
        $result->host = 'example.com';
        $result->service = 'host';
        $result->date = '20110511T120000Z';
        $result->requestBody = '';
        $result->authHeaderValue =
            'EMS-HMAC-SHA256 '.
            'Credential=th3K3y/20110511/us-east-1/host/aws4_request, '.
            'SignedHeaders=host;x-ems-date, '.
            'Signature=e7c1c7b2616d27ecbe3cd81ed3464ea4f6e2a11ad6f7792b23d67f7867e9abb4';
        $result->signedQueryParams =
            'X-EMS-Algorithm=EMS-HMAC-SHA256&'.
            'X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&'.
            'X-EMS-Date=20110511T120000Z&'.
            'X-EMS-Expires=123456&'.
            'X-EMS-SignedHeaders=host&'.
            'X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67';
        $result->requestUri = '/something?foo=bar&baz=barbaz&'. $result->signedQueryParams;
        return $result;
    }

    public function getTimeStamp()
    {
        return strtotime($this->date);
    }

    public function allHeaders($authHeaderName = 'authorization')
    {
        return $this->contentTypeHeader() + $this->hostHeader() + $this->dateHeader() + $this->authorizationHeader($authHeaderName);
    }

    public function authorizationHeader($authHeaderKey = 'authorization')
    {
        return array(strtolower($authHeaderKey) => $this->authorizationHeaderValue());
    }

    public function authorizationHeaderValue()
    {
        return $this->authHeaderValue;
    }

    public function shortDate()
    {
        return substr($this->date, 0, 8);
    }

    public function headerKeys()
    {
        return array_keys($this->headers);
    }

    public function createServer()
    {
        return AsrFacade::createServer($this->region, $this->service, $this->requestType, array($this->accessKeyId => $this->secretKey));
    }

    public function createClient()
    {
        return AsrFacade::createClient($this->secretKey, $this->accessKeyId, $this->region, $this->service, $this->requestType);
    }


    public function hostHeader()
    {
        return array('host' => $this->host);
    }
    public function tamperSignature()
    {
        $lastTenChars = substr($this->authorizationHeaderValue(), -60);
        return str_replace($lastTenChars, strrev($lastTenChars), $this->authorizationHeaderValue());
    }

    public function tamperHashAlgo()
    {
        return str_replace('SHA256', 'ASDA', $this->authorizationHeaderValue());
    }

    public function unsignHost()
    {
        return str_replace(';host', '', $this->authorizationHeaderValue());
    }

    public function unsignDate()
    {
        return str_replace(';x-ems-date', '', $this->authorizationHeaderValue());
    }

    public function tamperDate()
    {
        return strtotime(substr_replace($this->date, '11', 9, 2));
    }

    public function url()
    {
        return 'http://'.$this->host . '/';
    }

    public function defaultDateTime()
    {
        return new DateTime($this->date, new DateTimeZone("UTC"));
    }

    public function contentTypeHeader()
    {
        return array('content-type' => $this->contentType);
    }

    public function dateHeader($dateHeaderName = 'x-ems-date')
    {
        return array(strtolower($dateHeaderName) => $this->date);
    }

    public function defaultHeaders($dateHeaderName = 'x-ems-date')
    {
        return $this->contentTypeHeader() + $this->hostHeader() + $this->dateHeader($dateHeaderName);
    }
}
