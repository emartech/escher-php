<?php

namespace Escher\Test\Helper;

use DateTime;
use DateTimeZone;
use Escher\Escher;
use PHPUnit\Framework\TestCase;

abstract class TestBase extends TestCase
{
    protected function assertEqualMaps(array $expected, array $actual, string $message = '')
    {
        ksort($expected);
        ksort($actual);
        $this->assertEquals($expected, $actual, $message);
    }

    protected function createEscher(string $credentialScope = 'us-east-1/host/aws4_request'): Escher
    {
        return Escher::create($credentialScope)
            ->setAlgoPrefix('EMS')
            ->setVendorKey('EMS')
            ->setAuthHeaderKey('X-Ems-Auth')
            ->setDateHeaderKey('X-Ems-Date');
    }

    protected function getDate(): DateTime
    {
        return new DateTime('2011/05/11 12:00:00', new DateTimeZone('UTC'));
    }
}
