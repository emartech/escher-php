<?php

use Escher\Escher;

abstract class TestBase extends PHPUnit_Framework_TestCase
{
    protected function assertEqualMaps(array $expected, array $actual, $message = '')
    {
        ksort($expected);
        ksort($actual);
        $this->assertEquals($expected, $actual, $message);
    }

    /**
     * @param string $credentialScope
     * @return Escher
     */
    protected function createEscher($credentialScope = 'us-east-1/host/aws4_request')
    {
        return Escher::create($credentialScope)
            ->setAlgoPrefix('EMS')->setVendorKey('EMS')->setAuthHeaderKey('X-Ems-Auth')->setDateHeaderKey('X-Ems-Date');
    }

    /**
     * @return DateTime
     */
    protected function getDate()
    {
        return new DateTime('2011/05/11 12:00:00', new DateTimeZone("UTC"));
    }
}
