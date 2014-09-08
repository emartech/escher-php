<?php

class ValidateRequestTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldValidateRequestUsingAuthHeader()
    {
        $serverVars = array(
            'HTTP_X_EMS_DATE' => '20110909T233600Z',
            'HTTP_X_EMS_AUTH' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
            'REQUEST_TIME'    => strtotime('20110909T233600Z'),
            'REQUEST_METHOD'  => 'POST',
            'HTTP_HOST'       => 'iam.amazonaws.com',
            'CONTENT_TYPE'    => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI'     => '/',
            'HTTPS'           => '',
            'SERVER_PORT'     => '80',
            'SERVER_NAME'     => 'iam.amazonaws.com',
        );
        $keyDB = array('AKIDEXAMPLE' => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
        Escher::create('us-east-1/iam/aws4_request')->createServer($keyDB)
            ->validateRequest($serverVars, 'Action=ListUsers&Version=2010-05-08');
    }

    /**
     * @test
     * @dataProvider requestTamperingProvider
     */
    public function itShouldFailToValidateInvalidRequests($tamperedKey, $tamperedValue, $expectedErrorMessage)
    {
        $serverVars = array(
            'HTTP_X_EMS_DATE' => '20110909T233600Z',
            'HTTP_X_EMS_AUTH' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
            'REQUEST_TIME'    => strtotime('20110909T233600Z'),
            'REQUEST_METHOD'  => 'POST',
            'HTTP_HOST'       => 'iam.amazonaws.com',
            'CONTENT_TYPE'    => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI'     => '/',
            'HTTPS'           => '',
            'SERVER_PORT'     => '80',
            'SERVER_NAME'     => 'iam.amazonaws.com',
        );

        // replace server variable
        $serverVars[$tamperedKey] = $tamperedValue;

        $keyDB = array('AKIDEXAMPLE' => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');

        try {
            Escher::create('us-east-1/iam/aws4_request')->createServer($keyDB)->validateRequest($serverVars, 'Action=ListUsers&Version=2010-05-08');
            $this->fail('Should fail to validate!');
        } catch (EscherException $ex) {
            $this->assertStringStartsWith($expectedErrorMessage, $ex->getMessage());
        }
    }

    public function requestTamperingProvider()
    {
        return array(
            'wrong date'            => array('HTTP_X_EMS_DATE', strtotime('20110909T113600Z'), 'Invalid request date.'),
            'wrong request time'    => array('REQUEST_TIME',    strtotime('20110909T113600Z'), 'Request date is not within the accepted time interval.'),
            'wrong host'            => array('HTTP_HOST',       'example.com', 'The host header does not match.'),
            'wrong auth header'     => array('HTTP_X_EMS_AUTH', 'Malformed auth header', 'Could not parse authorization header.'),
            'tampered signature'    => array('HTTP_X_EMS_AUTH', 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'The signatures do not match'),
            'wrong hash algo'       => array('HTTP_X_EMS_AUTH', 'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd', 'Only SHA256 and SHA512 hash algorithms are allowed.'),
            'host not signed'       => array('HTTP_X_EMS_AUTH', 'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd', 'Host header not signed'),
            'date not signed'       => array('HTTP_X_EMS_AUTH', 'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd', 'Date header not signed'),
        );
    }

    /**
     * @test
     */
    public function itShouldValidateRequestUsingQueryString()
    {
        $serverVars = array(
            'REQUEST_TIME'    => strtotime('20110511T120000Z'),
            'REQUEST_METHOD'  => 'GET',
            'HTTP_HOST'       => 'example.com',
            'CONTENT_TYPE'    => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI'     => '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67',
            'HTTPS'           => '',
            'SERVER_PORT'     => '80',
            'SERVER_NAME'     => 'example.com',
        );
        $keyDB = array('th3K3y' => 'very_secure');
        Escher::create('us-east-1/host/aws4_request')->createServer($keyDB)->validateRequest($serverVars, '');
    }

    /**
     * @test
     * @expectedException EscherException
     * @expectedExceptionMessage The signatures do not match
     */
    public function itShouldFailToValidateInvalidQueryStrings()
    {
        $serverVars = array(
            'REQUEST_TIME'    => strtotime('20110511T120000Z'),
            'REQUEST_METHOD'  => 'GET',
            'HTTP_HOST'       => 'example.com',
            'CONTENT_TYPE'    => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI'     => '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=INFINITY&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67',
            'HTTPS'           => '',
            'SERVER_PORT'     => '80',
            'SERVER_NAME'     => 'example.com',
        );

        $keyDB = array('th3K3y' => 'very_secure');
        Escher::create('us-east-1/host/aws4_request')->createServer($keyDB)->validateRequest($serverVars, '');
    }
}
 