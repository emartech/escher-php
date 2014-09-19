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
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $actualHeaders = $this->createEscher($date)->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
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
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $this->createEscher($date)->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldAutomagicallyAddHostHeaderWithPort()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com:5000',
            'x-ems-date' => '20110909T233600Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=559b2e7df48ce2f6ab25af9a281ae40c26b87bb8d4387037bc4cdecd97f2f5a5',
        );
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $this->createEscher($date)->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com:5000/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
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
        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type');
        $actualHeaders = $this->createEscher($date)->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
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

        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $this->createEscher($date)->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldUseTheProvidedAuthHeaderName()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
        );
        $expectedHeaders = array(
            'content-type'       => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'               => 'iam.amazonaws.com',
            'x-ems-date'         => '20110909T233600Z',
            'custom-auth-header' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );

        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $this->createEscher($date, 'Custom-Auth-Header')->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldUseTheProvidedAlgoPrefix()
    {
        $inputHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
        );
        $expectedHeaders = array(
            'content-type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'host'         => 'iam.amazonaws.com',
            'x-ems-date'   => '20110909T233600Z',
            'x-ems-auth'   => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
        );

        $date = new DateTime('20110909T233600Z', new DateTimeZone("UTC"));
        $escher = Escher::create('us-east-1/iam/aws4_request', $date)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');
        $headersToSign = array('content-type', 'host', 'x-ems-date');
        $actualHeaders = $escher->signRequest(
            'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            'POST', 'http://iam.amazonaws.com/', 'Action=ListUsers&Version=2010-05-08', $inputHeaders, $headersToSign
        );
        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    /**
     * @test
     * @group sign_request
     */
    public function itShouldGenerateSignedHeaders()
    {
        $inputHeaders = array(
            'Some-Custom-Header' => 'FooBar'
        );

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $escher = Escher::create('us-east-1/host/aws4_request', $date)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');

        $actualHeaders = $escher->signRequest(
            'th3K3y', 'very_secure',
            'GET', 'http://example.com/something', '', $inputHeaders, array()
        );

        $expectedHeaders = array(
            'host' => 'example.com',
            'some-custom-header' => 'FooBar',
            'x-ems-date' => '20110511T120000Z',
            'x-ems-auth' => 'EMS-HMAC-SHA256 Credential=th3K3y/20110511/us-east-1/host/aws4_request, SignedHeaders=host;x-ems-date, Signature=e7c1c7b2616d27ecbe3cd81ed3464ea4f6e2a11ad6f7792b23d67f7867e9abb4',
        );

        $this->assertEqualMaps($expectedHeaders, $actualHeaders);
    }

    protected function createEscher($date, $authHeaderName = 'X-Ems-Auth')
    {
        return Escher::create('us-east-1/iam/aws4_request', $date)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey($authHeaderName)->setDateHeaderKey('X-Ems-Date');
    }
}
