<?php

namespace Escher\Test\Unit;

use Escher\RequestCanonicalizer;
use Escher\Test\Helper\TestBase;


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
}
