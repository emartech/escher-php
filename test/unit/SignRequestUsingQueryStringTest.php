<?php

class SignRequestUsingQueryStringTest extends TestBase
{
    /**
     * @test
     */
    public function itShouldGenerateSignedUrl()
    {
        $example = AsrExample::getCustom();
        $client = $example->createClient();

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $expires = 123456;
        $signedUrl = $client->getSignedUrl('http://example.com/something?foo=bar&baz=barbaz', $date, $expires);

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&' . $example->signedQueryParams;

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }

    /**
     * @test
     */
    public function itShouldAutomagicallyAddMandatoryHeaders()
    {
        $example = AsrExample::getCustom();
        $client = $example->createClient();

        $date = new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
        $expires = 123456;
        $signedUrl = $client->getSignedUrl('http://example.com/something?foo=bar&baz=barbaz', $date, $expires, array(), array());

        $expectedSignedUrl = 'http://example.com/something?foo=bar&baz=barbaz&' . $example->signedQueryParams;

        $this->assertEquals($expectedSignedUrl, $signedUrl);
    }
}
 