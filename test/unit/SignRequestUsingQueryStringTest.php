<?php

class SignRequestUsingQueryStringTest extends TestBase
{
    private $expires = 123456;

    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $signedUrl = $this->createEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com/something?foo=bar&baz=barbaz', $this->expires, $this->getDate());

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldHandlePort()
    {
        $signedUrl = $this->createEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com:5000/something?foo=bar&baz=barbaz', $this->expires, $this->getDate());

        $expectedSignedUrl = 'http://example.com:5000/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=7f7032b393945a0167fe65d35a7e2827a781ecab9019d814adf95c23bfa5e458';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldRespectWhenUrlHasLocationHash()
    {
        $signedUrl = $this->createEscher()->presignUrl('th3K3y', 'very_secure', 'http://example.com:5000/something?foo=bar&baz=barbaz#/client_fragment', $this->expires, $this->getDate());

        $expectedSignedUrl = 'http://example.com:5000/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=7f7032b393945a0167fe65d35a7e2827a781ecab9019d814adf95c23bfa5e458#/client_fragment';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldRespectWhenUrlHasSpecialChars()
    {
        $date = new DateTime('20150310T173248Z', new DateTimeZone('GMT'));
        $signedUrl = $this->createEscher('eu/service/ems_request')->presignUrl(
            'service_api_key',
            'service_secret',
            'https://service.example.com/login?id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name%3F',
            \Escher\Escher::DEFAULT_EXPIRES,
            $date
        );

        $expectedSignedUrl = 'https://service.example.com/login?id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host&X-EMS-Signature=661f2147c77b6784be5a60a8b842a96de6327653f1ed5d4305da43103c69a6f5';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }
}
