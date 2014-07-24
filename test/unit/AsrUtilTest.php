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
        $result = $this->util->generate('POST', 'http://iam.amazonaws.com/', $this->payload(), $this->headers(), array_keys($this->headers()));
        $this->assertEquals($this->canonicalHash(), $result);
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
        $date = '20120215';
        $result = $this->util->calculateSigningKey($date, $this->region(), $this->service(), $this->secretKey());
        $this->assertEquals($this->signingKey(), bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldSign()
    {
        $sign = $this->util->signRequest($this->stringToSign(), $this->date(), $this->region(), $this->service(), $this->secretKey());
        $this->assertEquals($this->signedRequest(), $sign);
    }

    /**
     * @return string
     */
    private function stringToSign()
    {
        return implode("\n", array(
            'AWS4-HMAC-SHA256', '20110909T233600Z', '20110909/us-east-1/iam/aws4_request', $this->canonicalHash()
        ));
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

    /**
     * @return string
     */
    private function signedRequest()
    {
        return 'ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c';
    }

    /**
     * @return string
     */
    private function secretKey()
    {
        return 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    }

    /**
     * @return string
     */
    private function service()
    {
        return 'iam';
    }

    /**
     * @return string
     */
    private function region()
    {
        return 'us-east-1';
    }

    /**
     * @return string
     */
    private function date()
    {
        return '20110909';
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
}
