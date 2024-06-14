<?php

namespace Escher\Test\Unit;

use DateTime;
use DateTimeZone;
use Escher\AuthElements;
use Escher\RequestHelper;
use Escher\Signer;
use Escher\Test\Helper\TestBase;

class InternalTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
    {
        $actualSigningKey = Signer::calculateSigningKey(
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
     */
    public function itShouldCollectBodyAndHeadersFromServerVariables()
    {
        $serverVars = [
            'REQUEST_TIME' => time(),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'iam.amazonaws.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/path?query=string'
        ];
        $requestBody = 'BODY';
        $helper = new RequestHelper($serverVars, $requestBody, 'Authorization', 'X-Ems-Date');
        $this->assertEquals($requestBody, $helper->getRequestBody());
        $expectedHeaders = [
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host' => 'iam.amazonaws.com',
        ];
        $this->assertEqualMaps($expectedHeaders, $helper->getHeaderList());
    }

    /**
     * @test
     * @dataProvider headerNames
     */
    public function itShouldParseAuthorizationHeader($authHeaderName, $dateHeaderName)
    {
        $headerList = [
            'host' => 'iam.amazonaws.com',
            $dateHeaderName => '20110909T233600Z',
            $authHeaderName => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        ];
        $authHeader = AuthElements::parseFromHeaders($headerList, $authHeaderName, $dateHeaderName, 'EMS');

        $this->assertEquals(new DateTime('20110909T233600Z', new DateTimeZone('GMT')), $authHeader->getDateTime());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals('us-east-1/iam/aws4_request', $authHeader->getCredentialScope());
        $this->assertEquals(['content-type', 'host', 'x-ems-date'], $authHeader->getSignedHeaders());
        $this->assertEquals('f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
            $authHeader->getSignature());
    }

    public function headerNames()
    {
        return [
            'default' => ['authorization', 'date'],
            'upcase' => ['Authorization', 'Date'],
            'custom' => ['x-ems-auth', 'x-ems-date'],
            'custom upcase' => ['X-Ems-Auth', 'X-Ems-Date'],
        ];
    }
}
