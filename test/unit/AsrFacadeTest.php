<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{
    private $allFixtures = array(
        'get-header-key-duplicate',
        'get-header-value-order',
        'get-header-value-trim',
        'get-relative-relative',
        'get-relative',
        'get-slash-dot-slash',
        'get-slash-pointless-dot',
        'get-slash',
        'get-slashes',
        'get-space',
        'get-unreserved',
        'get-utf8',
        'get-vanilla-empty-query-key',
        'get-vanilla-query-order-key-case',
        'get-vanilla-query-order-key',
        'get-vanilla-query-order-value',
        'get-vanilla-query-unreserved',
        'get-vanilla-query',
        'get-vanilla-ut8-query',
        'get-vanilla',
        'post-header-key-case',
        'post-header-key-sort',
        'post-header-value-case',
        'post-vanilla-empty-query-value',
        'post-vanilla-query-nonunreserved',
        'post-vanilla-query-space',
        'post-vanilla-query',
        'post-vanilla',
        'post-x-www-form-urlencoded-parameters',
        'post-x-www-form-urlencoded',
    );

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $example = AsrExample::getDefault();
        $headersToSign =  array('content-type','host','x-ems-date');
        $headerList = $example->getHeadersByKeys(array('content-type','host','x-ems-date'));
        $this->assertEquals($example->allHeaders(), $this->callSignRequest($example, $headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type','host','x-ems-date');
        $headerList = $example->getHeadersByKeys(array('content-type'));
        $this->assertEquals($example->allHeaders(), $this->callSignRequest($example, $headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type','host','x-ems-date');
        $extra = array('x-a-header' => 'that/should/not/be/signed');
        $contentType = $example->contentTypeHeader();

        $expected = $example->allHeaders() + $extra;
        ksort($expected);
        $this->assertEquals($expected, $this->callSignRequest($example, $contentType + $extra, $headersToSign));
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
            $example->getHeadersByKeys(array('content-type','host','x-ems-date')),
            $headersToSign,
            $example->defaultDateTime(),
            'Authorization'
        );
        $expected = $example->allHeaders();
        ksort($expected);
        $this->assertEquals($expected, $actual);
    }

    /**
     * @test
     */
    public function itShouldUseTheProvidedAuthHeaderName()
    {
        $example = AsrExample::getDefault();
        $headersToSign = array('content-type','host','x-ems-date');
        $_SERVER['REQUEST_TIME'] = $example->getTimeStamp();
        $actual = $example->createClient()->getSignedHeaders(
            $example->method,
            $example->url(),
            $example->requestBody,
            $example->getHeadersByKeys(array('content-type','host','x-ems-date')),
            $headersToSign,
            $example->defaultDateTime(),
            'CustomHeader'
        );
        $expected = $example->allHeaders('CustomHeader');
        ksort($expected);
        $this->assertEquals($expected, $actual);
    }

    /**
     * @test
     * @dataProvider authHeaderNames
     */
    public function itShouldParseAuthorizationHeader($authHeaderName)
    {
        $example = AsrExample::getDefault();
        $authHeader = AsrAuthHeader::parse(
            $example->authorizationHeader($authHeaderName) + $example->dateHeader() + $example->hostHeader(),
            $authHeaderName,
            'EMS'
        );

        $this->assertEquals($example->defaultEmsDate, $authHeader->getLongDate());
        $this->assertEquals($example->accessKeyId, $authHeader->getAccessKeyId());
        $this->assertEquals($example->shortDate(), $authHeader->getShortDate());
        $this->assertEquals($example->region, $authHeader->getRegion());
        $this->assertEquals($example->service, $authHeader->getService());
        $this->assertEquals($example->requestType, $authHeader->getRequestType());
        $this->assertEquals($example->headerKeys(), $authHeader->getSignedHeaders());
        $this->assertEquals($example->signature, $authHeader->getSignature());
    }

    public function authHeaderNames()
    {
        return array(
            'default'       => array('authorization'),
            'upcase'        => array('Authorization'),
            'custom'        => array('x-ems-auth'),
            'custom upcase' => array('X-Ems-Auth'),
        );
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
        $this->assertEquals($example->getHeadersByKeys(array('content-type', 'host')), $helper->getHeaderList());
        $this->assertEquals($requestBody, $helper->getRequestBody());
    }

    /**
     * @test
     */
    public function itShouldValidateRequestUsingAuthHeader()
    {
        $example = AsrExample::getDefault();
        $serverVars = $this->goodServerVars($example);
        $example->createServer()->validateRequest($serverVars, $example->requestBody);
    }

    /**
     * @test
     * @dataProvider requestTamperingProvider
     */
    public function itShouldFailForInvalidAuthHeader($tamperedKey, $tamperedValue, $expectedErrorMessage)
    {
        $example = AsrExample::getDefault();
        $serverVars = $this->goodServerVars($example);
        $serverVars[$tamperedKey] = $tamperedValue;
        $asrServer = $example->createServer();
        try {
            $asrServer->validateRequest($serverVars, $example->requestBody);
            $this->fail('Should fail to validate');
        } catch (AsrException $ex)
        {
            $this->assertEquals($expectedErrorMessage, $ex->getMessage());
        }
    }

    private function goodServerVars(AsrExample $example)
    {
        return array(
            'HTTP_X_EMS_DATE' => $example->defaultEmsDate,
            'HTTP_X_EMS_AUTH' => $example->authorizationHeaderValue(),
            'REQUEST_TIME' => $example->getTimeStamp() + rand(0, 100),
            'REQUEST_METHOD' => $example->method,
            'HTTP_HOST' => $example->host,
            'CONTENT_TYPE' => $example->contentType,
            'REQUEST_URI' => '/',
            'HTTPS' => null,
            'SERVER_PORT' => null,
            'SERVER_NAME' => $example->host,
        );
    }

    public function requestTamperingProvider()
    {
        $example = AsrExample::getDefault();
        return array(
            'wrong date'            => array('HTTP_X_EMS_DATE', '20110909T113600Z', 'One of the date headers are invalid'),
            'wrong auth header'     => array('HTTP_X_EMS_AUTH', '', 'Could not parse authorization header.'),
            'tampered signature'    => array('HTTP_X_EMS_AUTH', $example->tamperSignature(), 'The signatures do not match'),
            'wrong hash algo'       => array('HTTP_X_EMS_AUTH', $example->tamperHashAlgo(), 'Only SHA256 and SHA512 hash algorithms are allowed.'),
            'host not signed'       => array('HTTP_X_EMS_AUTH', $example->unsignHost(), 'Host header not signed'),
            'date not signed'       => array('HTTP_X_EMS_AUTH', $example->unsignDate(), 'Date header not signed'),
            'wrong request time'    => array('REQUEST_TIME', $example->tamperDate(), 'One of the date headers are invalid'),
            'wrong host'            => array('HTTP_HOST', 'example.com', 'The host header does not match.'),
        );
    }

    protected function createRequestHelper($serverVars, $requestBody)
    {
        return new AsrRequestHelper($serverVars, $requestBody, 'Authorization');
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

    private function processFixtures($input, $output)
    {
        $returnArray = array();
        foreach($this->allFixtures as $name) {
            $awsFixture = new AwsFixture($name);
            $returnArray[$name] = array($awsFixture->contents[$input], $awsFixture->contents[$output]);
        }
        return $returnArray;
    }

    /**
     * @test
     * @dataProvider StringToSignFileList
     */
    public function createStringToSign_Perfect_Perfect($canonicalRequestString, $expectedStringToSign)
    {
        $credentialScope = 'us-east-1/host/aws4_request';
        $actualStringToSign = AsrSigner::createStringToSign(
            $credentialScope,
            $canonicalRequestString,
            new DateTime("09 Sep 2011 23:36:00 GMT"),
            'sha256',
            'AWS4'
        );
        $this->assertEquals($expectedStringToSign, $actualStringToSign);
    }

    public function stringToSignFileList()
    {
        return $this->processFixtures('canonicalRequestString', 'stringToSign');
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

    /**
     * @test
     * @dataProvider headerFileList
     */
    public function createAuthHeader_Perfect_Perfect($stringToSign, $expectedAuthHeaders)
    {
        $matches = AsrAuthHeader::parseAuthHeader($expectedAuthHeaders, 'AWS4');

        list($accessKey, $credentialScope) = explode("/", $matches['credentials'], 2);

        $signingKey = $this->hex2bin("e220a8ee99f059729066fd06efe5c0f949d6aa8973360d189dd0e0eddd7a9596");
        $actualAuthHeader = AsrSigner::createAuthHeader(
            AsrSigner::createSignature($stringToSign, $signingKey, $matches['algorithm']),
            $credentialScope,
            $matches['signed_headers'],
            $matches['algorithm'],
            'AWS4',
            $accessKey
        );
        $this->assertEquals($expectedAuthHeaders, $actualAuthHeader);
    }

    public function headerFileList()
    {
        return $this->processFixtures('stringToSign', 'authHeader');
    }

    /**
     * @test
     * @dataProvider canonicalizeFixtures
     */
    public function canonicalize_Perfect_Perfect($rawRequest, $canonicalRequestString)
    {
        list($method, $requestUri, $body, $headerLines) = $this->parseRawRequest($rawRequest);
        $headersToSign = array();
        foreach ($headerLines as $headerLine) {
            if ("\t" != $headerLine{0} && false !== strpos($headerLine, ':')) {
                list ($headerKey) = explode(':', $headerLine, 2);
                $headersToSign[]= $headerKey;
            }
        }
        $canonicalizedRequest = AsrRequestCanonicalizer::canonicalize(
            $method,
            $requestUri,
            $body,
            implode("\n", $headerLines),
            array_unique(array_map('strtolower', $headersToSign)),
            'sha256'
        );
        $this->assertEquals($canonicalRequestString, $canonicalizedRequest);
    }

    public function canonicalizeFixtures()
    {
        return $this->processFixtures('rawRequest', 'canonicalRequestString');
    }

    private function parseRawRequest($content)
    {
        $rows = explode("\n", $content);
        list($method, $requestUri) = explode(' ', $rows[0]);

        return array(
            $method,
            $requestUri,
            $rows[count($rows) - 1],
            array_slice($rows, 1, -2),
        );
    }


    /**
     * @test
     */
    public function getSignedHeaders_EveryParameterSet_ReturnsSignedHeaders()
    {
        $party = new AsrParty('us-east-1', 'host', 'aws4_request');
        $secret = "very_secure";
        $key = "th3K3y";

        $hashAlgo = "sha256";
        $vendorPrefix = "EMS";

        $client = new AsrClient($party, $secret, $key, $hashAlgo, $vendorPrefix);

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $signedHeaders = $client->getSignedHeaders(
            "GET",
            "http://example.com/something",
            "",
            array('Some-Custom-Header' => 'FooBar'),
            array('Host', 'X-Ems-Date'),
            $date,
            'x-ems-auth'
        );

        $expectedSignedHeaders = array(
            'some-custom-header' => 'FooBar',
            'host'               => 'example.com',
            'x-ems-date'         => '20110511T120000Z',
            'x-ems-auth'         => 'EMS-HMAC-SHA256 Credential=th3K3y/20110511/us-east-1/host/aws4_request, SignedHeaders=host;x-ems-date, Signature=e7c1c7b2616d27ecbe3cd81ed3464ea4f6e2a11ad6f7792b23d67f7867e9abb4'
        );

        $this->assertEquals($expectedSignedHeaders, $signedHeaders);
    }

    public function hex2bin($hexstr)
    {
        $n = strlen($hexstr);
        $sbin="";
        $i=0;
        while($i<$n)
        {
            $a =substr($hexstr,$i,2);
            $c = pack("H*",$a);
            if ($i==0){$sbin=$c;}
            else {$sbin.=$c;}
            $i+=2;
        }
        return $sbin;
    }
}

class AwsFixture
{
    public $contents;

    public function __construct($name)
    {
        $this->contents = $this->load($name);
    }

    private function load($request)
    {
        $path = $this->awsFixtures();

        return array(
            "rawRequest"             => file_get_contents($path . $request . ".req"),
            "canonicalRequestString" => file_get_contents($path . $request . ".creq"),
            "stringToSign"           => file_get_contents($path . $request . ".sts"),
            "authHeader"             => file_get_contents($path . $request . ".authz"),
        );
    }

    /**
     * @return string
     */
    private function awsFixtures()
    {
        return dirname(__FILE__) . '/../fixtures/aws4_testsuite/';
    }
}

class AsrExample
{
    public $defaultEmsDate;
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

    /**
     * @return AsrExample
     */
    public static function getDefault()
    {
        $result = new AsrExample();
        $result->defaultEmsDate = '20110909T233600Z';
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
            'x-ems-date' => $result->defaultEmsDate,
        );
        return $result;
    }

    public function getTimeStamp()
    {
        return strtotime($this->defaultEmsDate);
    }

    public function getHeadersByKeys($headerKeys)
    {
        $result = array();
        foreach ($this->headers as $key => $value) {
            if (in_array($key, $headerKeys)) {
                $result[$key] = $value;
            }
        }
        return $result;
    }

    public function allHeaders($authHeaderName = 'authorization')
    {
        $result = $this->contentTypeHeader() + $this->hostHeader() + $this->dateHeader() + $this->authorizationHeader($authHeaderName);
        ksort($result);
        return $result;
    }

    public function authorizationHeader($authHeaderKey = 'authorization')
    {
        return array(strtolower($authHeaderKey) => $this->authorizationHeaderValue());
    }

    public function authorizationHeaderValue()
    {
        return
            'EMS-HMAC-SHA256 '.
            'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
            'SignedHeaders=content-type;host;x-ems-date, '.
            'Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd';
    }

    public function shortDate()
    {
        return substr($this->defaultEmsDate, 0, 8);
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
        return strtotime(substr_replace($this->defaultEmsDate, '11', 9, 2));
    }

    public function url()
    {
        return 'http://'.$this->host . '/';
    }

    public function defaultDateTime()
    {
        return new DateTime($this->defaultEmsDate, new DateTimeZone("UTC"));
    }

    public function contentTypeHeader()
    {
        return array('content-type' => $this->contentType);
    }

    public function dateHeader()
    {
        return array('x-ems-date' => $this->defaultEmsDate);
    }
}
