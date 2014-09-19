<?php

class SignRequestUsingQueryStringTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $escher = Escher::create('us-east-1/host/aws4_request', $date)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');

        $expires = 123456;
        $signedUrl = $escher->presignUrl('th3K3y', 'very_secure', 'http://example.com/something?foo=bar&baz=barbaz', $expires);

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }
    /**
     * @test
     */
    public function itShouldHandlePort()
    {
        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $escher = Escher::create('us-east-1/host/aws4_request', $date)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');

        $expires = 123456;
        $signedUrl = $escher->presignUrl('th3K3y', 'very_secure', 'http://example.com:5000/something?foo=bar&baz=barbaz', $expires);

        $expectedSignedUrl = 'http://example.com:5000/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=7f7032b393945a0167fe65d35a7e2827a781ecab9019d814adf95c23bfa5e458';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }
}
