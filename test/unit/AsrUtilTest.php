<?php

class AsrUtilTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var AsrUtil
     */
    private $util;

    protected function setUp()
    {
        $this->util = new AsrUtil(new SigningAlgorithm(SigningAlgorithm::SHA_256));
    }

    /**
     * @test
     */
    public function itShouldSignRequest()
    {
        $result = $this->util->signRequest($this->secretKey(), $this->fullDate(), 'POST', 'http://iam.amazonaws.com/', $this->payload(), $this->headers());
        $this->assertEquals($this->signedRequest(), $result);
    }

    /**
     * @test
     */
    public function itShouldGenerateCanonicalHash()
    {
        $result = $this->util->generateCanonicalHash('POST', 'http://iam.amazonaws.com/', $this->payload(), $this->headers(), array_keys($this->headers()));
        $this->assertEquals($this->canonicalHash(), $result);
    }

    /**
     * @test
     */
    public function itShouldGenerateStringToSign()
    {
        $result = $this->util->generateStringToSign($this->fullDate(), $this->credentialScope(), $this->canonicalHash());
        $this->assertEquals($this->stringToSign(), $result);
    }

    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $shortDate = '20120215';
        $result = $this->util->generateSigningKey($shortDate, $this->region(), $this->service(), $this->secretKey());
        $this->assertEquals($this->signingKey(), bin2hex($result));
    }

    /**
     * @test
     */
    public function itShouldSignString()
    {
        $result = $this->util->sign($this->stringToSign(), $this->shortDate(), $this->region(), $this->service(), $this->secretKey());
        $this->assertEquals($this->signedRequest(), $result);
    }

    /**
     * @return string
     */
    private function stringToSign()
    {
        return implode("\n", array('AWS4-HMAC-SHA256', $this->fullDate(), $this->credentialScope(), $this->canonicalHash()));
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
    private function shortDate()
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

    /**
     * @return string
     */
    private function fullDate()
    {
        return '20110909T233600Z';
    }
    /**
     * @return string
     */
    private function credentialScope()
    {
        return implode('/', array($this->shortDate(), $this->region(), $this->service(), 'aws4_request'));
    }
}
