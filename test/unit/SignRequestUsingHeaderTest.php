<?php

class SignRequestUsingHeaderTest extends TestBase
{
    /**
     * @test
     * @group sign_request
     */
    public function itShouldSignRequest()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
            'x-ems-date' => '20110909T233600Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );
        $headersToSign =  array('content-type', 'host', 'x-ems-date');
        $client = AsrFacade::createClient('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'AKIDEXAMPLE', 'us-east-1', 'iam', 'aws4_request');
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $actualHeaders = $client->getSignedHeaders('POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign, $date);
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldAutomagicallyAddHostHeader()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
            'x-ems-date' => '20110909T233600Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );
        $client = AsrFacade::createClient('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'AKIDEXAMPLE', 'us-east-1', 'iam', 'aws4_request');
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $client->getSignedHeaders('POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign, $date);
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldAutomagicallyAddDateAndHostToSignedHeaders()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
            'x-ems-date' => '20110909T233600Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );
        $client = AsrFacade::createClient('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'AKIDEXAMPLE', 'us-east-1', 'iam', 'aws4_request');
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type');
        $actualHeaders = $client->getSignedHeaders('POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign, $date);
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldOnlySignHeadersExplicitlySetToBeSigned()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'x-a-header' => 'that/should/not/be/signed',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
            'x-a-header' => 'that/should/not/be/signed',
            'x-ems-date' => '20110909T233600Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );

        $client = AsrFacade::createClient('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'AKIDEXAMPLE', 'us-east-1', 'iam', 'aws4_request');
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $client->getSignedHeaders('POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign, $date);
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     */
    public function itShouldUseTheProvidedAuthHeaderName()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'x-a-header' => 'that/should/not/be/signed',
        );
        $expectedHeaders = array(
            'content-type'       => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'               => 'iam.amazonaws.com',
            'x-a-header'         => 'that/should/not/be/signed',
            'x-ems-date'         => '20110909T233600Z',
            'custom-auth-header' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );

        $client = AsrFacade::createClient('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'AKIDEXAMPLE', 'us-east-1', 'iam', 'aws4_request');
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $client->getSignedHeaders(
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign, $date, 'Custom-Auth-Header'
        );
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }
}
