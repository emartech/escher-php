<?php

class InternalTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldCalculateSigningKey()
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
     */
    public function itShouldCollectBodyAndHeadersFromServerVariables()
    {
        $example = AsrExample::getDefault();
        $serverVars = array(
            'REQUEST_TIME' => time(),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'iam.amazonaws.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/path?query=string'
        );
        $requestBody = 'BODY';
        $helper = new AsrRequestHelper($serverVars, $requestBody, 'Authorization', 'X-Ems-Date');
        $this->assertEquals($requestBody, $helper->getRequestBody());
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host' => 'iam.amazonaws.com',
        );
        $this->assertEqualMaps($expectedHeaders, $helper->getHeaderList());
    }
}
