<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{
    private $defaultAmzDate = '20110909T233600Z';
    /**
     * @var AsrSigningAlgorithm
     */
    private $algorithm;

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
     * @param $requestTime
     * @return AsrRequestToValidate
     */
    public function requestHeadersToValidate($requestTime)
    {
        $request = AsrRequestToValidate::create(array(
            'REQUEST_URI' => '/',
            'REQUEST_TIME' => strtotime($requestTime),
            'HTTP_X_AMZ_DATE' => $this->defaultAmzDate,
            'HTTP_AUTHORIZATION' => $this->authorizationHeader()
        ), '');
        return $request;
    }

    protected function setUp()
    {
        $this->algorithm = new AsrSigningAlgorithm(AsrFacade::SHA256);
    }

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $headersToSign = array('Content-Type');
        $headerList = $this->headers();
        $this->assertEquals($this->authorizationHeaders(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $headerList = array('Content-Type' => $this->contentType);
        $headersToSign = array('Content-Type');
        $this->assertEquals($this->authorizationHeaders(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $headerList = array(
            'Content-Type' => $this->contentType,
            'X-A-Header' => 'that/should/not/be/signed'
        );
        $headersToSign = array('Content-Type');
        $this->assertEquals($this->authorizationHeaders(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @param $headerList
     * @param $headersToSign
     * @return array
     */
    public function callSignRequestWithDefaultParams($headerList, $headersToSign)
    {
        return $this->defaultClient()->signRequest('POST', $this->url(), $this->requestBody(), $headerList, $headersToSign, strtotime($this->defaultAmzDate));
    }

    /**
     * @test
     */
    public function itShouldUseTheServersRequestTimeAsTheFullDate()
    {
        $headerList = $this->headers();
        $headersToSign = array('Content-Type');
        $_SERVER['REQUEST_TIME'] = strtotime($this->defaultAmzDate);
        $actual = $this->defaultClient()->signRequest('POST', $this->url(), $this->requestBody(), $headerList, $headersToSign);
        $this->assertEquals($this->authorizationHeaders(), $actual);
    }

    /**
     * @test
     */
    public function itShouldGenerateCanonicalHash()
    {
        $headers = AsrHeaders::createFrom($this->headers(), array_keys($this->headers()));
        $request = new AsrRequestToSign('POST', '/', '', $this->requestBody());
        $result = $request->canonicalizeUsing($this->algorithm, $headers);
        $this->assertEquals('3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2', $result);
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $credentials = new AsrCredentials($this->accessKeyId, array($this->region, $this->service, $this->requestType));
        $result = $credentials->generateSigningKeyUsing($this->algorithm, $this->secretKey, '20120215TIRRELEVANT');
        $this->assertEquals('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d', bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldParseAuthorizationHeader()
    {
        $headerList = $this->authorizationHeaders();
        $authHeader = AsrAuthHeader::parse($headerList);

        $this->assertEquals($this->defaultAmzDate, $authHeader->getLongDate());
        $this->assertEquals('SHA256', $authHeader->getAlgorithm());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals(array('content-type', 'host', 'x-amz-date'), $authHeader->getSignedHeaders());
        $this->assertEquals('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c', $authHeader->getSignature());
    }

    /**
     * @test
     */
    public function itShouldParseHeaders()
    {
        $request = AsrRequestToValidate::create(
            array(
                'HTTP_HOST' => $this->host,
                'HTTP_CONTENT_TYPE' => $this->contentType,
                'REQUEST_URI' => '/path?query=string'
        ), 'BODY');
        $this->assertEquals(array('host' => $this->host, 'content-type' => $this->contentType), $request->getHeaderList());
        $this->assertEquals('/path', $request->getPath());
        $this->assertEquals('query=string', $request->getQuery());
        $this->assertEquals('BODY', $request->getBody());
    }

    /**
     * @test
     */
    public function itShouldNotAllowTimeDifferencesLargerThanFifteenMinutes()
    {
        $requestTime = '20110909T235300Z';
        $request = $this->requestHeadersToValidate($requestTime);
        $server = new AsrServer();
        $actual = $server->validateDates($request);
        $this->assertFalse($actual);
    }

    /**
     * @test
     */
    public function itShouldAllowTimeDifferencesSmallerThanFifteenMinutes()
    {
        $requestTime = '20110909T233200Z';
        $request = $this->requestHeadersToValidate($requestTime);
        $server = new AsrServer();
        $actual = $server->validateDates($request);
        $this->assertTrue($actual);
    }

    /**
     * @return array
     */
    private function headers()
    {
        return array(
            'Content-Type' => $this->contentType,
            'Host' => $this->host,
            'X-Amz-Date' => $this->defaultAmzDate,
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
     * @return array
     */
    private function authorizationHeaders()
    {
        return array(
            'Authorization' => $this->authorizationHeader(),
            'X-Amz-Date'    => $this->defaultAmzDate,
        );
    }

    private function authorizationHeader()
    {
        return
            'AWS4-HMAC-SHA256 '.
            'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
            'SignedHeaders=content-type;host;x-amz-date, '.
            'Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
    }
}
