<?php

class AsrFacadeTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var AsrFacade
     */
    private $util;

    /**
     * @var AsrSigningAlgorithm
     */
    private $algorithm;

    private $secretKey = 'AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    private $accessKeyId = 'AKIDEXAMPLE';
    private $baseCredentials = array('us-east-1', 'iam', 'aws4_request');
    private $host = 'iam.amazonaws.com';

    protected function setUp()
    {
        $this->util = new AsrFacade();
        $this->algorithm = new AsrSigningAlgorithm(AsrFacade::SHA256);
    }

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $headersToSign = array('Content-Type');
        $headerList = $this->headers();
        $this->assertEquals($this->authorizationHeader(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $headerList = array('Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8');
        $headersToSign = array('Content-Type');
        $this->assertEquals($this->authorizationHeader(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @test
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $headerList = array(
            'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'X-A-Header' => 'that/should/not/be/signed'
        );
        $headersToSign = array('Content-Type');
        $this->assertEquals($this->authorizationHeader(), $this->callSignRequestWithDefaultParams($headerList, $headersToSign));
    }

    /**
     * @param $headerList
     * @param $headersToSign
     * @return array
     */
    public function callSignRequestWithDefaultParams($headerList, $headersToSign)
    {
        return AsrBuilder::create(strtotime('20110909T233600Z'))
            ->useRequest('POST', '/', '', $this->payload())
            ->useCredentials($this->accessKeyId, $this->baseCredentials)
            ->useHeaders($this->host, $headerList, $headersToSign)
            ->buildAuthHeaders($this->secretKey);
    }

    /**
     * @test
     */
    public function itShouldUseSha256AsDefaultAlgorithm()
    {
        $headerList = $this->headers();
        $headersToSign = array('Content-Type');
        $actual = AsrBuilder::create(strtotime('20110909T233600Z'))
            ->useRequest('POST', '/', '', $this->payload())
            ->useCredentials($this->accessKeyId, $this->baseCredentials)
            ->useHeaders($this->host, $headerList, $headersToSign)
            ->buildAuthHeaders($this->secretKey);
        $this->assertEquals($this->authorizationHeader(), $actual);
    }

    /**
     * @test
     */
    public function itShouldUseTheServersRequestTimeAsTheFullDate()
    {
        $headerList = $this->headers();
        $headersToSign = array('Content-Type');
        $_SERVER['REQUEST_TIME'] = strtotime('20110909T233600Z');
        $actual = AsrBuilder::create()
            ->useRequest('POST', '/', '', $this->payload())
            ->useCredentials($this->accessKeyId, $this->baseCredentials)
            ->useHeaders($this->host, $headerList, $headersToSign)
            ->buildAuthHeaders($this->secretKey);
        $this->assertEquals($this->authorizationHeader(), $actual);
    }

    /**
     * @test
     */
    public function itShouldGenerateCanonicalHash()
    {
        $headers = AsrHeaders::createFrom($this->headers(), array_keys($this->headers()));
        $request = new AsrRequest('POST', '/', '', $this->payload());
        $result = $request->canonicalizeUsing($this->algorithm, $headers);
        $this->assertEquals('3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2', $result);
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $credentials = new AsrCredentials($this->accessKeyId, $this->baseCredentials);
        $result = $credentials->generateSigningKeyUsing($this->algorithm, $this->secretKey, '20120215TIRRELEVANT');
        $this->assertEquals('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d', bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldParseAuthorizationHeader()
    {
        $headerList = $this->authorizationHeader();
        $authHeader = AsrBuilder::parseAuthHeader($headerList['Authorization']);

        $this->assertEquals('SHA256', $authHeader->getAlgorithm());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals(array('AKIDEXAMPLE', '20110909', 'us-east-1', 'iam', 'aws4_request'), $authHeader->getCredentialParts());
        $this->assertEquals(array('content-type', 'host', 'x-amz-date'), $authHeader->getSignedHeaders());
        $this->assertEquals('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c', $authHeader->getSignature());
    }

    /**
     * @test
     */
    public function itShouldThrowExceptionIfDatesAreTooFarApart()
    {
        $validator = new AsrValidator();
        $actual = $validator->validateDates('20110909T233600Z', '20110909T232500Z', '20110909');
        $this->assertFalse($actual);
    }

    /**
     * @test
     */
    public function itShouldNotThrowExceptionsIfDatesAreAcceptable()
    {
        $validator = new AsrValidator();
        $actual = $validator->validateDates('20110909T233600Z', '20110909T233200Z', '20110909');
        $this->assertTrue($actual);
    }

    /**
     * @return array
     */
    private function headers()
    {
        return array(
            'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'Host' => $this->host,
            'X-Amz-Date' => '20110909T233600Z',
        );
    }

    /**
     * @return string
     */
    private function payload()
    {
        return 'Action=ListUsers&Version=2010-05-08';
    }

    /**
     * @return array
     */
    private function authorizationHeader()
    {
        return array(
            'Authorization' =>
                'AWS4-HMAC-SHA256 '.
                'Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, '.
                'SignedHeaders=content-type;host;x-amz-date, '.
                'Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c',
            'X-Amz-Date'    => '20110909T233600Z',
        );
    }
}
