<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{
    private $defaultEmsDate = '20110909T233600Z';
    private $secretKey = 'AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    private $accessKeyId = 'AKIDEXAMPLE';
    private $region = 'us-east-1';
    private $service = 'iam';
    private $requestType = 'aws4_request';
    private $host = 'iam.amazonaws.com';
    private $contentType = 'application/x-www-form-urlencoded; charset=utf-8';

    /**
     * @return string
     */
    public function url()
    {
        return 'http://'.$this->host . '/';
    }

    /**
     * @return AsrClient
     */
    public function defaultClient()
    {
        return AsrFacade::createClient($this->secretKey, $this->accessKeyId, $this->region, $this->service, $this->requestType);
    }

    /**
     * @return AsrServer
     */
    public function defaultServer()
    {
        return AsrFacade::createServer($this->region, $this->service, $this->requestType, array($this->accessKeyId => $this->secretKey));
    }

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $headersToSign = array('content-type','host','x-ems-date');
        $headerList = $this->headers();
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $headerList = array('content-type' => $this->contentType);
        $headersToSign = array('content-type','host','x-ems-date');
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $headerList = array(
            'content-type' => $this->contentType,
            'x-a-header' => 'that/should/not/be/signed'
        );
        $headersToSign = array('content-type','host','x-ems-date');
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldUseTheServersRequestTimeAsTheFullDate()
    {
        $headerList = $this->headers();
        $headersToSign = array('content-type','host','x-ems-date');
        $_SERVER['REQUEST_TIME'] = strtotime($this->defaultEmsDate);
        $actual = $this->defaultClient()->getSignedHeaders('POST', $this->url(), $this->requestBody(), $headerList, $headersToSign, $this->defaultDateTime());
        $this->assertEquals($this->authorizationHeaders(AsrFacade::DEFAULT_AUTH_HEADER_KEY) + $headerList + $this->hostHeader(), $actual);
    }

    /**
     * @test
     */
    public function itShouldParseAuthorizationHeader()
    {
        $headerList = $this->authorizationHeaders();
        $authHeader = AsrAuthHeader::parse($headerList, 'authorization');

        $this->assertEquals($this->defaultEmsDate, $authHeader->getLongDate());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals($this->region, $authHeader->getRegion());
        $this->assertEquals($this->service, $authHeader->getService());
        $this->assertEquals($this->requestType, $authHeader->getRequestType());
        $this->assertEquals(array('content-type','host','x-ems-date'), $authHeader->getSignedHeaders());
        $this->assertEquals('89fedf8ddad1397d53fdbe4767687ef58d488a32026b2db18c41b128178bc095', $authHeader->getSignature());
    }

    /**
     * @test
     */
    public function itShouldParseHeaders()
    {
        $serverVars = array(
            'REQUEST_TIME' => time(),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => $this->host,
            'CONTENT_TYPE' => $this->contentType,
            'REQUEST_URI' => '/path?query=string'
        );
        $requestBody = 'BODY';
        $helper = $this->createRequestHelper($serverVars, $requestBody);
        $this->assertEquals(array('host' => $this->host, 'content-type' => $this->contentType), $helper->getHeaderList());
        $this->assertEquals('BODY', $helper->getRequestBody());
    }

    /**
     * @test
     */
    public function itShouldValidateRequest()
    {
        $serverVars = $this->goodServerVars();
        $this->defaultServer()->validateRequest($serverVars, $this->requestBody());
    }

    /**
     * @test
     * @dataProvider requestTamperingProvider
     */
    public function itShouldFailForInvalidRequest($tamperedKey, $tamperedValue, $expectedErrorMessage)
    {
        $serverVars = $this->goodServerVars();
        $serverVars[$tamperedKey] = $tamperedValue;
        $asrServer = $this->defaultServer();
        $requestBody = $this->requestBody();
        try
        {
            $asrServer->validateRequest($serverVars, $requestBody);
            $this->fail('Should fail to validate');
        }
        catch (AsrException $ex)
        {
            $this->assertEquals($expectedErrorMessage, $ex->getMessage());
        }
    }

    /**
     * @return array
     */
    private function goodServerVars()
    {
        return array(
            'HTTP_X_EMS_DATE' => $this->defaultEmsDate,
            'HTTP_X_EMS_AUTH' => $this->authorizationHeader(),
            'REQUEST_TIME' => strtotime($this->defaultEmsDate) + rand(0, 100),
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => $this->host,
            'CONTENT_TYPE' => $this->contentType,
            'REQUEST_URI' => '/',
            'HTTPS' => null,
            'SERVER_PORT' => null,
            'SERVER_NAME' => $this->host,
        );
    }

    public function requestTamperingProvider()
    {
        return array(
            'wrong date'            => array('HTTP_X_EMS_DATE', '20110909T113600Z', 'One of the date headers are invalid'),
            'wrong auth header'     => array('HTTP_X_EMS_AUTH', '', 'Could not parse authorization header.'),
            'tampered signature'    => array('HTTP_X_EMS_AUTH', $this->headerWithTamperedSignature(), 'The signatures do not match'),
            'wrong hash algo'       => array('HTTP_X_EMS_AUTH', $this->headerWithWrongHashAlgo(), 'Only SHA256 and SHA512 hash algorithms are allowed.'),
            'host not signed'       => array('HTTP_X_EMS_AUTH', $this->headerWithHostNotSigned(), 'Host header not signed'),
            'date not signed'       => array('HTTP_X_EMS_AUTH', $this->headerWithDateNotSigned(), 'Date header not signed'),
            'wrong request time'    => array('REQUEST_TIME', strtotime('20110909T113600Z'), 'One of the date headers are invalid'),
            'wrong host'            => array('HTTP_HOST', 'example.com', 'The host header does not match.'),
        );
    }

    /**
     * @return string
     */
    private function headerWithTamperedSignature()
    {
        $lastTenChars = substr($this->authorizationHeader(), -60);
        return str_replace($lastTenChars, strrev($lastTenChars), $this->authorizationHeader());
    }

    private function headerWithWrongHashAlgo()
    {
        return str_replace('SHA256', 'ASDA', $this->authorizationHeader());
    }

    private function headerWithHostNotSigned()
    {
        return str_replace(';host', '', $this->authorizationHeader());
    }

    private function headerWithDateNotSigned()
    {
        return str_replace(';x-ems-date', '', $this->authorizationHeader());
    }

    /**
     * @return array
     */
    private function headers()
    {
        return array(
            'content-type' => $this->contentType,
            'host' => $this->host,
            'x-ems-date' => $this->defaultEmsDate,
        );
    }

    /**
     * @return string
     */
    private function requestBody()
    {
        return 'Action=ListUsers&Version=2010-05-08';
    }

    /**
     * @param string $headerKey
     * @return array
     */
    private function authorizationHeaders($headerKey = 'Authorization')
    {
        return array(
            $headerKey   => $this->authorizationHeader(),
            'x-ems-date' => $this->defaultEmsDate,
            'host'       => $this->host
        );
    }

    private function authorizationHeader()
    {
        return
            'EMS-HMAC-SHA256 '.
            'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
            'SignedHeaders=content-type;host;x-ems-date, '.
            'Signature=89fedf8ddad1397d53fdbe4767687ef58d488a32026b2db18c41b128178bc095';
    }

    /**
     * @param $serverVars
     * @param $requestBody
     * @return AsrRequestHelper
     */
    protected function createRequestHelper($serverVars, $requestBody)
    {
        return new AsrRequestHelper($serverVars, $requestBody, 'Authorization');
    }

    /**
     * @param $headerList
     * @param $headersToSign
     * @return array
     */
    public function callSignRequestWithDefaultParams($headerList, $headersToSign)
    {
        return $this->defaultClient()->getSignedHeaders('POST', $this->url(), $this->requestBody(), $headerList, $headersToSign, $this->defaultDateTime(), 'Authorization');
    }

    private function hostHeader()
    {
        return array('host' => $this->host);
    }

    /**
     * @param $headerList
     * @return array
     */
    protected function allHeaders($headerList)
    {
        return $headerList + $this->authorizationHeaders() + $this->hostHeader();
    }

    /**
     * @return DateTime
     */
    private function defaultDateTime()
    {
        return new DateTime($this->defaultEmsDate, new DateTimeZone("UTC"));
    }

    private $testFiles = array(
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
//        'post-vanilla-query-nonunreserved',
        'post-vanilla-query-space',
        'post-vanilla-query',
        'post-vanilla',
        'post-x-www-form-urlencoded-parameters',
        'post-x-www-form-urlencoded',
    );

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

        $pattern = '/'.
            '^AWS4-HMAC-(?P<algorithm>[A-Z0-9\,]+) ' .
            'Credential=(?P<credentials>[A-Za-z0-9\/\-_]+), '.
            'SignedHeaders=(?P<signed_headers>[a-z\-;]+), '.
            'Signature=(?P<signature>[0-9a-f]{64})'.
            '$/';
        preg_match($pattern, $expectedAuthHeaders, $matches);

        list($accessKey, $credentialScope) = explode("/", $matches['credentials'], 2);

        $signerKey = hex2bin("e220a8ee99f059729066fd06efe5c0f949d6aa8973360d189dd0e0eddd7a9596");
        $signedHeaders = $matches['signed_headers'];

        $actualAuthHeader = AsrSigner::createAuthHeader(
            AsrSigner::createSignature($stringToSign, $signerKey, $matches['algorithm']),
            $credentialScope,
            $signedHeaders,
            $matches['algorithm'],
            'AWS4',
            $accessKey
        );
        $this->assertEquals($expectedAuthHeaders, $actualAuthHeader);
    }

    public function stringToSignFileList()
    {
        $returnArray = array();
        foreach($this->testFiles as $file) {
            $awsFixture = $this->getRequestContents($file);
            $returnArray[$file] = array($awsFixture['canonicalRequestString'], $awsFixture['stringToSign']);
        }

        return $returnArray;
    }

    public function headerFileList()
    {
        $returnArray = array();
        foreach($this->testFiles as $file) {
            $awsFixture = $this->getRequestContents($file);
            $returnArray[$file] = array($awsFixture['stringToSign'], $awsFixture['authHeader']);
        }

        return $returnArray;
    }

    private function getRequestContents($request)
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

    /**
     * @test
     * @dataProvider canonicalizeFixtures
     */
    public function canonicalize_Perfect_Perfect($rawRequest, $canonicalRequestString)
    {
        $rawRequestArray = $this->parseRawRequest($rawRequest);
        $headersToSign = array_unique(array_map('strtolower', array_keys($rawRequestArray['headers'])));
        $canonicalizedRequest = AsrRequestCanonicalizer::canonicalize(
            $rawRequestArray['method'],
            $rawRequestArray['path'],
            $rawRequestArray['query'],
            $rawRequestArray['body'],
            $rawRequestArray['headers'],
            $headersToSign,
            'sha256'
        );
        $this->assertEquals($canonicalRequestString, $canonicalizedRequest);
    }

    public function canonicalizeFixtures()
    {
        $returnArray = array();
        foreach($this->testFiles as $file) {
            $awsFixture = $this->getRequestContents($file);
            $returnArray[$file] = array($awsFixture['rawRequest'], $awsFixture['canonicalRequestString']);
        }

        return $returnArray;
    }

    private function parseRawRequest($content)
    {
        $rows = explode("\n", $content);
        $pattern = "/^(?P<method>GET|POST|PUT) (?P<path>.*)(\?(?P<query>.*))? http\/1\.1$/U";
        preg_match($pattern, $rows[0], $matches);
        unset($rows[0]);

        $headerRows = array();
        foreach ($rows as $key => $row) {
            if ($row == "") {
                unset($rows[$key]);
                break;
            }
            $headerRows[] = $row;
            unset($rows[$key]);
        }
        $body = implode("\n", $rows);
        $headers = http_parse_headers($headerRows);

        $query = isset($matches['query']) ? $matches['query'] : "";
        $headers = $headers ? $headers : array();
        $body = isset($body) ? $body : "";

        return array(
            'method'  => $matches['method'],
            'path'    => $matches['path'],
            'query'   => $query,
            'headers' => $headers,
            'body'    => $body
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
}

if (!function_exists('http_parse_headers'))
{
    function http_parse_headers($rawHeaderLines)
    {
        $headers = array();
        $previousKey = ''; // [+]

        foreach($rawHeaderLines as $headerLine) {
            $headerLine = explode(':', $headerLine, 2);

            if (isset($headerLine[1])) {
                $currentKey = strtolower($headerLine[0]);
                $headers[$currentKey] = array_merge(isset($headers[$currentKey]) ? $headers[$currentKey] : array(), array(trim($headerLine[1])));
                $previousKey = $currentKey;
            } else {
                $trimmedValuePart = trim($headerLine[0]);
                if ($headerLine[0]{0} == "\t") {
                    $headers[$previousKey][count($headers[$previousKey] - 1)] .= ' '. $trimmedValuePart;
                } elseif (!$previousKey) {
                    $headers[0] = array($trimmedValuePart);
                }
            }
        }

        return array_reduce(array_map('implode_header_multivalues', array_keys($headers), array_values($headers)), 'array_merge', array());
    }

    function implode_header_multivalues($key, $value)
    {
        sort($value);
        return array($key => implode(',', $value));
    }
}
