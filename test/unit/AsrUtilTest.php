<?php

class AsrUtilTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var AsrUtil
     */
    private $util;

    protected function setUp()
    {
        $this->util = new AsrUtil();
    }

    /**
     * @test
     */
    public function itShouldGenerateSignedRequestHeader()
    {
        $headers = array(
            'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'Host' => 'iam.amazonaws.com',
            'X-Amz-Date' => '20110909T233600Z',
        );
        $signedHeaders = array_keys($headers);
        $payload = 'Action=ListUsers&Version=2010-05-08';
        $result = $this->util->generate('POST', 'http://iam.amazonaws.com/', $payload, $headers, $signedHeaders);
        $this->assertEquals('3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2', $result);
    }

    /**
     * @test
     */
    public function itShouldGenerateStringToSign()
    {
        $algo = 'AWS4-HMAC-SHA256';
        $date = '20110909T233600Z';
        $canonicalRequestHash = $this->canonicalHash();
        $credentialScope = '20110909/us-east-1/iam/aws4_request';
        $result = $this->util->createStringToSign($algo, $date, $credentialScope, $canonicalRequestHash);
        $this->assertEquals($this->stringToSign(), $result);
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $result = $this->util->calculateSigningKey('20120215', 'us-east-1', 'iam', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
        $this->assertEquals($this->signingKey(), bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldSign()
    {
        $sign = $this->util->signRequest($this->stringToSign(), '20110909', 'us-east-1', 'iam', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
        $this->assertEquals('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c', $sign);
    }

    /**
     * @return string
     */
    private function stringToSign()
    {
        return "AWS4-HMAC-SHA256
20110909T233600Z
20110909/us-east-1/iam/aws4_request
3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";
    }

    /**
     * @return string
     */
    private function canonicalHash()
    {
        return '3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2';
    }

    /**
     * @return string
     */
    private function signingKey()
    {
        return 'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d';
    }
}
