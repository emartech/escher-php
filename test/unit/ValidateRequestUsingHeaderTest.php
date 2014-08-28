<?php

class ValidateRequestUsingHeaderTest extends TestBase
{
    /**
     * @test
     * @dataProvider headerNames
     */
    public function itShouldParseAuthorizationHeader($authHeaderName, $dateHeaderName)
    {
        $example = AsrExample::getDefault();
        $authHeader = AsrAuthElements::parseFromHeaders(
            $example->authorizationHeader($authHeaderName) + $example->dateHeader($dateHeaderName) + $example->hostHeader(),
            $authHeaderName,
            $dateHeaderName,
            'EMS'
        );

        $this->assertEquals('20110909T233600Z', $authHeader->getLongDate());
        $this->assertEquals('AKIDEXAMPLE', $authHeader->getAccessKeyId());
        $this->assertEquals('20110909', $authHeader->getShortDate());
        $this->assertEquals('us-east-1', $authHeader->getRegion());
        $this->assertEquals('iam', $authHeader->getService());
        $this->assertEquals('aws4_request', $authHeader->getRequestType());
        $this->assertEquals(array('content-type', 'host', 'x-ems-date'), $authHeader->getSignedHeaders());
        $this->assertEquals('f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd', $authHeader->getSignature());
    }

    public function headerNames()
    {
        return array(
            'default'       => array('authorization', 'date'),
            'upcase'        => array('Authorization', 'Date'),
            'custom'        => array('x-ems-auth',    'x-ems-date'),
            'custom upcase' => array('X-Ems-Auth',    'X-Ems-Date'),
        );
    }
}
