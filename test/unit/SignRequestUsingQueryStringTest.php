<?php

class SignRequestUsingQueryStringTest extends TestBase
{
    private $expires = 123456;

    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $signedUrl = $this->getEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com/something?foo=bar&baz=barbaz', $this->expires);

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldHandlePort()
    {
        $signedUrl = $this->getEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com:5000/something?foo=bar&baz=barbaz', $this->expires);

        $expectedSignedUrl = 'http://example.com:5000/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=7f7032b393945a0167fe65d35a7e2827a781ecab9019d814adf95c23bfa5e458';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldRespectWhenUrlHasLocationHash()
    {
        $signedUrl = $this->getEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com:5000/something?foo=bar&baz=barbaz#/client_fragment', $this->expires);

        $expectedSignedUrl = 'http://example.com:5000/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=7f7032b393945a0167fe65d35a7e2827a781ecab9019d814adf95c23bfa5e458#/client_fragment';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @return DateTime
     */
    private function getDate()
    {
        return new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
    }

    /**
     * @return Escher
     */
    private function getEscher()
    {
        return Escher::create('us-east-1/host/aws4_request', $this->getDate())
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');
    }
}
