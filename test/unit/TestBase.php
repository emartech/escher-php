<?php

abstract class TestBase extends PHPUnit_Framework_TestCase
{
    protected function assertEqualMaps(array $expected, array $actual, $message = '')
    {
        ksort($expected);
        ksort($actual);
        $this->assertEquals($expected, $actual, $message);
    }
}
