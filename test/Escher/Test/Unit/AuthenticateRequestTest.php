<?php

namespace Escher\Test\Unit;

use Escher;
use Escher\Exception;
use Escher\Test\Helper\TestBase;
use Escher\Utils;


class AuthenticateRequestTest extends TestBase
{
    /**
     * @test
     * @throws Exception
     */
    public function itShouldAuthenticateRequestUsingAuthHeader()
    {
        $serverVars = [
            'HTTP_X_EMS_DATE' => '20110909T233600Z',
            'HTTP_X_EMS_AUTH' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
            'REQUEST_TIME' => $this->strtotime('20110909T233600Z'),
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => 'iam.amazonaws.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/',
            'HTTPS' => '',
            'SERVER_PORT' => '80',
            'SERVER_NAME' => 'iam.amazonaws.com',
        ];
        $keyDB = ['AKIDEXAMPLE' => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'];
        $accessKeyId = $this->createEscher('us-east-1/iam/aws4_request')
            ->authenticate($keyDB, $serverVars, 'Action=ListUsers&Version=2010-05-08');
        $this->assertEquals('AKIDEXAMPLE', $accessKeyId);
    }

    /**
     * @test
     * @dataProvider validPortProvider
     * @param $httpHost
     * @param $serverName
     * @param $serverPort
     * @param $https
     * @param $signature
     * @throws Exception
     */
    public function itShouldAuthenticateRequestRegardlessDefaultPortProvidedOrNot(
        $httpHost,
        $serverName,
        $serverPort,
        $https,
        $signature
    ) {
        $serverVars = [
            'HTTP_X_EMS_DATE' => '20110909T233600Z',
            'HTTP_X_EMS_AUTH' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=' . $signature,
            'REQUEST_TIME' => $this->strtotime('20110909T233600Z'),
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => $httpHost,
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/',
            'HTTPS' => $https,
            'SERVER_PORT' => $serverPort,
            'SERVER_NAME' => $serverName,
        ];
        $keyDB = ['AKIDEXAMPLE' => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'];
        $accessKeyId = $this->createEscher('us-east-1/iam/aws4_request')
            ->authenticate($keyDB, $serverVars, 'Action=ListUsers&Version=2010-05-08');
        $this->assertEquals('AKIDEXAMPLE', $accessKeyId);
    }

    public function validPortProvider()
    {
        return [
            'default http port not provided' => [
                'iam.amazonaws.com',
                'iam.amazonaws.com',
                '80',
                '',
                'f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd'
            ],
            'default http port provided' => [
                'iam.amazonaws.com:80',
                'iam.amazonaws.com',
                '80',
                '',
                'f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd'
            ],
            'default https port not provided' => [
                'iam.amazonaws.com',
                'iam.amazonaws.com',
                '443',
                'on',
                'f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd'
            ],
            'default https port provided' => [
                'iam.amazonaws.com:443',
                'iam.amazonaws.com',
                '443',
                'on',
                'f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd'
            ],
            'custom http port' => [
                'iam.amazonaws.com:123',
                'iam.amazonaws.com',
                '123',
                '',
                '9584a4a527986bbbead79b56523d50e1c8161155933a644674d0b2f2a0bce19a'
            ],
            'custom https port' => [
                'iam.amazonaws.com:123',
                'iam.amazonaws.com',
                '123',
                'on',
                '9584a4a527986bbbead79b56523d50e1c8161155933a644674d0b2f2a0bce19a'
            ],
            'default http port as custom https port' => [
                'iam.amazonaws.com:80',
                'iam.amazonaws.com',
                '80',
                'on',
                'b5daefdecb7124f47fafad18549e18a1a9c5accc4216a146c919d0635eccc370'
            ],
            'default https port as custom http port' => [
                'iam.amazonaws.com:443',
                'iam.amazonaws.com',
                '443',
                '',
                'b36c465c5a6bb79e6c6ac666e9c3847d5c997e035321429b7c25777ea86af35c'
            ]
        ];
    }

    /**
     * @test
     * @dataProvider requestTamperingProvider
     * @param $tamperedKey
     * @param $tamperedValue
     * @param $expectedErrorMessage
     * @param $expectedErrorCode
     * @throws Exception
     */
    public function itShouldFailToValidateInvalidRequests(
        $tamperedKey,
        $tamperedValue,
        $expectedErrorMessage,
        $expectedErrorCode
    ) {
        $serverVars = [
            'HTTP_X_EMS_DATE' => '20110909T233600Z',
            'HTTP_X_EMS_AUTH' => 'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
            'REQUEST_TIME' => $this->strtotime('20110909T233600Z'),
            'REQUEST_METHOD' => 'POST',
            'HTTP_HOST' => 'iam.amazonaws.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/',
            'HTTPS' => '',
            'SERVER_PORT' => '80',
            'SERVER_NAME' => 'iam.amazonaws.com',
        ];

        // replace server variable
        $serverVars[$tamperedKey] = $tamperedValue;

        $keyDB = ['AKIDEXAMPLE' => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'];

        try {
            $this->createEscher('us-east-1/iam/aws4_request')
                ->authenticate($keyDB, $serverVars, 'Action=ListUsers&Version=2010-05-08');
            $this->fail('Should fail to validate!');
        } catch (Exception $ex) {
            $this->assertStringStartsWith($expectedErrorMessage, $ex->getMessage());
            $this->assertEquals($expectedErrorCode, $ex->getCode());
        }
    }

    public function requestTamperingProvider()
    {
        return [
            'wrong auth header' => [
                'HTTP_X_EMS_AUTH',
                'Malformed auth header',
                'Could not parse auth header',
                2002
            ],
            'wrong date' => [
                'HTTP_X_EMS_DATE',
                'INVALIDDATE',
                'Date header is invalid, the expected format is 20151104T092022Z',
                2004
            ],
            'invalid Escher key' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA256 Credential=FOOBAR/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
                'Invalid Escher key',
                3001
            ],
            'wrong hash algo' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
                'Only SHA256 and SHA512 hash algorithms are allowed',
                3002
            ],
            'invalid credential' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-2/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
                'The credential scope is invalid',
                3003
            ],
            'host not signed' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;x-ems-date, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
                'The host header is not signed',
                4001
            ],
            'date not signed' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA123 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host, Signature=f36c21c6e16a71a6e8dc56673ad6354aeef49c577a22fd58a190b5fcf8891dbd',
                'The x-ems-date header is not signed',
                4002
            ],
            'wrong request time' => [
                'REQUEST_TIME',
                '20110909T113600Z',
                'The request date is not within the accepted time range',
                5001
            ],
            'tampered signature' => [
                'HTTP_X_EMS_AUTH',
                'EMS-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-ems-date, Signature=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                'The signatures do not match',
                6001
            ],
        ];
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidateRequestUsingQueryString()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20110511T120000Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67',
            'HTTPS' => '',
            'SERVER_PORT' => '80',
            'SERVER_NAME' => 'example.com',
        ];
        $keyDB = ['th3K3y' => 'very_secure'];

        $accessKeyId = $this->createEscher('us-east-1/host/aws4_request')->authenticate($keyDB, $serverVars, '');
        $this->assertEquals('th3K3y', $accessKeyId);
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidatePresignedUrlRequestWithSpecialCharacters()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20150310T173248Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'service.example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/login?id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host&X-EMS-Signature=661f2147c77b6784be5a60a8b842a96de6327653f1ed5d4305da43103c69a6f5',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => 'service.example.com',
        ];
        $keyDB = ['service_api_key' => 'service_secret'];

        $accessKeyId = $this->createEscher('eu/service/ems_request')->authenticate($keyDB, $serverVars);
        $this->assertEquals('service_api_key', $accessKeyId);
    }

    /**
     * @test
     */
    public function itShouldFailToValidateInvalidQueryStrings()
    {
        $this->expectException(Escher\Exception::class);
        $this->expectExceptionMessage('The signatures do not match');
        $this->expectExceptionCode(6001);
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20110511T120000Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=' . PHP_INT_MAX . '&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67',
            'HTTPS' => '',
            'SERVER_PORT' => '80',
            'SERVER_NAME' => 'example.com',
        ];

        $keyDB = ['th3K3y' => 'very_secure'];
        $this->createEscher('us-east-1/host/aws4_request')->authenticate($keyDB, $serverVars, '');
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidatePresignedUrlRequestWithUnindexedArray()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20150310T173248Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'service.example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/login?id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name&param1%5B%5D=1&param1%5B%5D=2%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host&X-EMS-Signature=ddb1e6479f28752c23a2a7f12fa54d3f21c4b36b8247e88e5992975a10ba616c',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => 'service.example.com',
        ];
        $keyDB = ['service_api_key' => 'service_secret'];

        $accessKeyId = $this->createEscher('eu/service/ems_request')->authenticate($keyDB, $serverVars);
        $this->assertEquals('service_api_key', $accessKeyId);
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidatePresignedUrlRequestWithIndexedArray()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20150310T173248Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'service.example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/login?id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name&param1%5B0%5D=1&param1%5B1%5D=2%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host&X-EMS-Signature=196bc22e36ea13d2bfe59c3fb42fbf67a09ec501a79924284d9281d7d8c773ce',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => 'service.example.com',
        ];
        $keyDB = ['service_api_key' => 'service_secret'];

        $accessKeyId = $this->createEscher('eu/service/ems_request')->authenticate($keyDB, $serverVars);
        $this->assertEquals('service_api_key', $accessKeyId);
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidatePresignedUrlIfSignatureIsTheFirstParam()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20150310T173248Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'service.example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/login?X-EMS-Signature=196bc22e36ea13d2bfe59c3fb42fbf67a09ec501a79924284d9281d7d8c773ce&id=12345678&domain=login.example.com&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name&param1%5B0%5D=1&param1%5B1%5D=2%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => 'service.example.com',
        ];
        $keyDB = ['service_api_key' => 'service_secret'];

        $accessKeyId = $this->createEscher('eu/service/ems_request')->authenticate($keyDB, $serverVars);
        $this->assertEquals('service_api_key', $accessKeyId);
    }

    /**
     * @test
     * @throws Exception
     */
    public function itShouldValidatePresignedUrlIfSignatureIsInTheMiddleOfTheQueryString()
    {
        $serverVars = [
            'REQUEST_TIME' => $this->strtotime('20150310T173248Z'),
            'REQUEST_METHOD' => 'GET',
            'HTTP_HOST' => 'service.example.com',
            'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=utf-8',
            'REQUEST_URI' => '/login?id=12345678&domain=login.example.com&X-EMS-Signature=196bc22e36ea13d2bfe59c3fb42fbf67a09ec501a79924284d9281d7d8c773ce&redirect_to=https%3A%2F%2Fhome.dev%2Fbootstrap.php%3Fr%3Dservice%2Findex%26service%3Dservice_name&param1%5B0%5D=1&param1%5B1%5D=2%3F&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=service_api_key%2F20150310%2Feu%2Fservice%2Fems_request&X-EMS-Date=20150310T173248Z&X-EMS-Expires=86400&X-EMS-SignedHeaders=host',
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => 'service.example.com',
        ];
        $keyDB = ['service_api_key' => 'service_secret'];

        $accessKeyId = $this->createEscher('eu/service/ems_request')->authenticate($keyDB, $serverVars);
        $this->assertEquals('service_api_key', $accessKeyId);
    }

    /**
     * @param $dateString
     * @return string
     * @throws Exception
     */
    private function strtotime($dateString)
    {
        return Utils::parseLongDate($dateString)->format('U');
    }
}

