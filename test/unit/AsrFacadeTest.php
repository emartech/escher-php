<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{
    private $defaultAmzDate = '20110909T233600Z';
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
        $headersToSign = array('Content-Type');
        $headerList = $this->headers();
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $headerList = array('Content-Type' => $this->contentType);
        $headersToSign = array('Content-Type');
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
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
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
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
        $this->assertEquals($this->authorizationHeaders(AsrFacade::DEFAULT_AUTH_HEADER_KEY) + $headerList + $this->hostHeader(), $actual);
    }

    /**
     * @test
     */
    public function itShouldParseAuthorizationHeader()
    {
        $headerList = $this->authorizationHeaders();
        $authHeader = AsrAuthHeader::parse($headerList, 'authorization');

        $this->assertEquals($this->defaultAmzDate, $authHeader->getLongDate());
        $this->assertEquals(AsrHashAlgorithm::create(AsrFacade::SHA256), $authHeader->createAlgorithm());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals($this->region, $authHeader->getRegion());
        $this->assertEquals($this->service, $authHeader->getService());
        $this->assertEquals($this->requestType, $authHeader->getRequestType());
        $this->assertEquals(array('content-type', 'host', 'x-amz-date'), $authHeader->getSignedHeaders());
        $this->assertEquals('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c', $authHeader->getSignature());
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
        $request = $helper->createRequest();
        $this->assertEquals(array('host' => $this->host, 'content-type' => $this->contentType), $helper->getHeaderList());
        $this->assertEquals('/path', $request->getPath());
        $this->assertEquals('query=string', $request->getQuery());
        $this->assertEquals('BODY', $request->getBody());
    }

    /**
     * @test
     */
    public function itShouldValidateRequest()
    {
        $serverVars = array(
            'HTTP_X_AMZ_DATE' => $this->defaultAmzDate,
            'HTTP_X_AMZ_AUTH' => $this->authorizationHeader(),
            'REQUEST_TIME' => strtotime($this->defaultAmzDate) + rand(0, 100),
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => $this->host,
            'CONTENT_TYPE' => $this->contentType,
            'REQUEST_URI' => '/'
        );
        $this->defaultServer()->validateRequest($serverVars, $this->requestBody());
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
     * @param string $headerKey
     * @return array
     */
    private function authorizationHeaders($headerKey = 'Authorization')
    {
        return array(
            $headerKey   => $this->authorizationHeader(),
            'X-Amz-Date' => $this->defaultAmzDate,
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
        return $this->defaultClient()->signRequest('POST', $this->url(), $this->requestBody(), $headerList, $headersToSign, strtotime($this->defaultAmzDate), 'SHA256', 'Authorization');
    }

    private function hostHeader()
    {
        return array('Host' => $this->host);
    }

    /**
     * @param $headerList
     * @return array
     */
    protected function allHeaders($headerList)
    {
        return $this->authorizationHeaders() + $headerList + $this->hostHeader();
    }
}
