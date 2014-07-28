<?php

class AsrUtilTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var AsrUtil
     */
    private $util;

    /**
     * @var AsrSigningAlgorithm
     */
    private $algorithm;

    private $secretKey = 'AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    private $accessKeyId = 'AKIDEXAMPLE';
    private $baseCredentials = array('us-east-1', 'iam', 'aws4_request');

    protected function setUp()
    {
        $this->util = new AsrUtil();
        $this->algorithm = new AsrSigningAlgorithm(AsrUtil::SHA256);
    }

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $this->assertEquals($this->authorizationHeader(), $this->util->signRequest(
            AsrUtil::SHA256,
            $this->secretKey,
            $this->accessKeyId,
            $this->baseCredentials,
            '20110909T233600Z',
            'POST',
            $this->url(),
            $this->payload(),
            $this->headers(),
            array('Content-Type')
        ));
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddDateAndHostHeader()
    {
        $this->assertEquals($this->authorizationHeader(), $this->util->signRequest(
            AsrUtil::SHA256,
            $this->secretKey,
            $this->accessKeyId,
            $this->baseCredentials,
            '20110909T233600Z',
            'POST',
            $this->url(),
            $this->payload(),
            array('Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8'),
            array('Content-Type')
        ));
    }

    /**
     * @test
     */
    public function itShouldGenerateCanonicalHash()
    {
        $headers = AsrHeaders::createFrom($this->headers(), array_keys($this->headers()));
        $request = new AsrRequest('POST', '/', '', $this->payload(), $headers);
        $result = $request->canonicalizeUsing($this->algorithm);
        $this->assertEquals('3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2', $result);
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $credentials = new AsrCredentials('20120215TIRRELEVANT', $this->accessKeyId, $this->baseCredentials);
        $result = $credentials->generateSigningKeyUsing($this->algorithm, $this->secretKey);
        $this->assertEquals('f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d', bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldParseAuthorizationHeader()
    {
        $headerList = $this->authorizationHeader();
        $actual = AsrAuthHeader::parse($headerList['Authorization']);
        $this->assertEquals('SHA256', $actual['algorithm']);
        $this->assertEquals('AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request', $actual['credentials']);
        $this->assertEquals('content-type;host;x-amz-date', $actual['signed_headers']);
        $this->assertEquals('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c', $actual['signature']);
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
            'Host' => 'iam.amazonaws.com',
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
     * @return string
     */
    private function url()
    {
        return 'http://iam.amazonaws.com/';
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
