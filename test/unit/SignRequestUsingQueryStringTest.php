<?php

class SignRequestUsingQueryStringTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $client = Escher::create('us-east-1/host/aws4_request', $date)->createClient('very_secure', 'th3K3y');

        $expires = 123456;
        $signedUrl = $client->presignUrl('http://example.com/something?foo=bar&baz=barbaz', $expires);

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67';

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }
}
