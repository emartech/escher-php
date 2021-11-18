<?php

use Escher\RequestCanonicalizer;


class RequestCanonicalizerTest extends TestBase
{
    /**
     * @test
     */
    public function urlEncodeQueryStringShouldNotReplacePlusSign()
    {
        $query = "email=test%2Bbayxd%40gmail.com";
        $result = RequestCanonicalizer::urlEncodeQueryString($query, "application/json");
        $this->assertEquals($query, $result);
    }

    /**
     * @test
     */
    public function  urlEncodeQueryStringShouldReplacePlusSignWithSplace()
    {
        $query = "email=test%2Bbayxd%40gmail.com";
        $expected = "email=test%20bayxd%40gmail.com";
        $result = RequestCanonicalizer::urlEncodeQueryString($query, "Content-Type: application/x-www-form-urlencoded");
        $this->assertEquals($expected, $result);
    }
}