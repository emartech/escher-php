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
        $headersToSign = array('content-type');
        $headerList = $this->headers();
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $headerList = array('content-type' => $this->contentType);
        $headersToSign = array('content-type');
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $headerList = array(
            'content-type' => $this->contentType,
            'X-A-Header' => 'that/should/not/be/signed'
        );
        $headersToSign = array('content-type');
        $this->assertEquals($this->allHeaders($headerList), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldUseTheServersRequestTimeAsTheFullDate()
    {
        $headerList = $this->headers();
        $headersToSign = array('content-type');
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
        $this->assertEquals(array('content-type'), $authHeader->getSignedHeaders());
        $this->assertEquals('ac112ad5285453a5a4631928f7cd26a0731d894b23c5564fa8d3dd847a8cf8ff', $authHeader->getSignature());
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
        $this->assertEquals('BODY', $request->getBody());
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
            'wrong request time'    => array('REQUEST_TIME', strtotime('20110909T113600Z'), 'One of the date headers are invalid'),
            'wrong host'            => array('HTTP_HOST', 'example.com', 'The host header does not match.'),
        );
    }

    /**
     * @return string
     */
    private function headerWithTamperedSignature()
    {
        return rtrim($this->authorizationHeader(), 'f') . 'aa';
    }

    private function headerWithWrongHashAlgo()
    {
        return str_replace('SHA256', 'ASDA', $this->authorizationHeader());
    }

    /**
     * @return array
     */
    private function headers()
    {
        return array(
            'Content-Type' => $this->contentType,
            'Host' => $this->host,
            'X-Ems-Date' => $this->defaultEmsDate,
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
            'X-Ems-Date' => $this->defaultEmsDate,
            'Host'       => $this->host
        );
    }

    private function authorizationHeader()
    {
        return
            'EMS-HMAC-SHA256 '.
            'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
            'SignedHeaders=content-type, '.
            'Signature=ac112ad5285453a5a4631928f7cd26a0731d894b23c5564fa8d3dd847a8cf8ff';
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
        return array('Host' => $this->host);
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
}
