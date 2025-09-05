<?php

namespace Escher\Test\EndToEnd;

use Escher\Escher;
use Escher\Exception;
use Escher\Test\Helper\JsonTestCase;
use PHPUnit\Framework\TestCase;

class CentralTest extends TestCase
{
    private static $ignoredTestCases = [
        'emarsys_testsuite/signrequest/get-header-value-order' => 'PHP does not handle multiple headers with the same name directly, the server before PHP does the conversion into the comma separated list',
        'emarsys_testsuite/signrequest/get-header-key-duplicate' => 'PHP does not handle multiple headers with the same name directly, the server before PHP does the conversion into the comma separated list',
        'test_cases/signrequest/error-invalid-request-url' => 'Not applicable for the PHP implementation',
        'test_cases/authenticate/error-post-body-null' => 'Not applicable for the PHP implementation',
        'test_cases/authenticate/error-invalid-request-url' => 'Not applicable for the PHP implementation',
    ];

    public function signRequestTestCases()
    {
        $data = [];
        foreach (JsonTestCase::getTestCases('signrequest') as $testCase) {
            $data["{$testCase->suite}/{$testCase->type}/{$testCase->name}"] = [$testCase];
        }
        return $data;
    }

    public function authenticateTestCases()
    {
        $data = [];
        foreach (JsonTestCase::getTestCases('authenticate') as $testCase) {
            $data["{$testCase->suite}/{$testCase->type}/{$testCase->name}"] = [$testCase];
        }
        return $data;
    }

    public function presignUrlTestCases()
    {
        $data = [];
        foreach (JsonTestCase::getTestCases('presignurl') as $testCase) {
            $data["{$testCase->suite}/{$testCase->type}/{$testCase->name}"] = [$testCase];
        }
        return $data;
    }

    /**
     * @test
     * @dataProvider signRequestTestCases
     */
    public function signRequestTests(JsonTestCase $testCase)
    {
        if (array_key_exists("{$testCase->suite}/{$testCase->type}/{$testCase->name}", self::$ignoredTestCases)) {
            $this->markTestSkipped(self::$ignoredTestCases["{$testCase->suite}/{$testCase->type}/{$testCase->name}"]);
        }

        $escher = $this->getEscher($testCase);

        $request = $testCase->getRequest();

        try {
            $host = $request['headers']['Host'] ?? $request['headers']['host'];
            $signedHeaders = $escher->signRequest(
                $testCase->getApiKey(),
                $testCase->getApiSecret(),
                $request['method'],
                'https://' . $host . $request['url'],
                $request['body'],
                $request['headers'],
                $testCase->getHeadersToSign(),
                $testCase->getCurrentTime()
            );

            if ($testCase->hasExpectedCanonicalizedRequest()) {
                $this->assertEquals($testCase->getExpectedCanonicalizedRequest(), $escher->debugInfo['canonicalizedRequest']);
            }
            if ($testCase->hasExpectedStringToSign()) {
                $this->assertEquals($testCase->getExpectedStringToSign(), $escher->debugInfo['stringToSign']);
            }
            if ($testCase->hasExpectedHeaders()) {
                $this->assertEquals($testCase->getExpectedHeaders(), $signedHeaders);
            } else {
                $this->fail('no request in expected');
            }
        } catch (Exception $e) {
            if ($testCase->hasExpectedError()) {
                $this->assertEquals($testCase->getExpectedError(), $e->getMessage());
            } else {
                throw $e;
            }
        }
    }

    /**
     * @test
     * @dataProvider authenticateTestCases
     */
    public function authenticateTests(JsonTestCase $testCase)
    {
        if (array_key_exists("{$testCase->suite}/{$testCase->type}/{$testCase->name}", self::$ignoredTestCases)) {
            $this->markTestSkipped(self::$ignoredTestCases["{$testCase->suite}/{$testCase->type}/{$testCase->name}"]);
        }

        $escher = $this->getEscher($testCase);

        $request = $testCase->getRequest();
        $serverVars = [
            'REQUEST_METHOD' => $request['method'],
            'REQUEST_URI' => $request['url'],
            'REQUEST_TIME' => $testCase->getCurrentTime()->format('U'),
            'HTTPS' => 'on',
            'SERVER_PORT' => '443',
            'SERVER_NAME' => $request['headers']['Host'] ?? $request['headers']['host'] ?? null,
        ];
        foreach ($request['headers'] as $k => $v) {
            $serverVars['HTTP_' . str_replace('-', '_', strtoupper($k))] = $v;
        }

        try {
            $apiKey = $escher->authenticate($testCase->getKeyDb(), $serverVars, $request['body'] ?? null, $testCase->getMandatorySignedHeaders());
            if ($testCase->hasExpectedApiKey()) {
                $this->assertEquals($testCase->getExpectedApiKey(), $apiKey);
            } else {
                $this->fail('no apiKey in expected');
            }
        } catch (Exception $e) {
            if ($testCase->hasExpectedError()) {
                $this->assertEquals($testCase->getExpectedError(), $e->getMessage());
            } else {
                throw $e;
            }
        }
    }

    /**
     * @test
     * @dataProvider presignUrlTestCases
     */
    public function presignUrlTests(JsonTestCase $testCase)
    {
        if (array_key_exists("{$testCase->suite}/{$testCase->type}/{$testCase->name}", self::$ignoredTestCases)) {
            $this->markTestSkipped(self::$ignoredTestCases["{$testCase->suite}/{$testCase->type}/{$testCase->name}"]);
        }

        $escher = $this->getEscher($testCase);

        $request = $testCase->getRequest();
        $url = $escher->presignUrl(
            $testCase->getApiKey(),
            $testCase->getApiSecret(),
            $request['url'],
            $request['expires'],
            $testCase->getCurrentTime()
        );

        $this->assertEquals($testCase->getExpectedUrl(), $url);
    }

    private function getEscher(JsonTestCase $testCase): Escher
    {
        $escher = Escher::create($testCase->getCredentialScope());
        if ($testCase->getAlgoPrefix()) {
            $escher->setAlgoPrefix($testCase->getAlgoPrefix());
        }
        if ($testCase->getVendorKey()) {
            $escher->setVendorKey($testCase->getVendorKey());
        }
        if ($testCase->getHashAlgo()) {
            $escher->setHashAlgo($testCase->getHashAlgo());
        }
        if ($testCase->getAuthHeaderName()) {
            $escher->setAuthHeaderKey($testCase->getAuthHeaderName());
        }
        if ($testCase->getDateHeaderName()) {
            $escher->setDateHeaderKey($testCase->getDateHeaderName());
        }

        return $escher;
    }
}
