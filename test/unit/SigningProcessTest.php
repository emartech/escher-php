<?php

class SigningProcessTest extends PHPUnit_Framework_TestCase
{
    private $amazonFixtures = array(
        'get-vanilla',
        'post-vanilla',
        'get-vanilla-query',
        'post-vanilla-query',
        'get-vanilla-empty-query-key',
        'post-vanilla-empty-query-value',
        'get-vanilla-query-order-key',
        'post-x-www-form-urlencoded',
        'post-x-www-form-urlencoded-parameters',

        'get-header-value-trim',
//        'get-header-key-duplicate',
        'post-header-key-case',
        'post-header-key-sort',
//        'get-header-value-order',
        'post-header-value-case',

        'get-vanilla-query-order-value',
        'get-vanilla-query-order-key-case',
        'get-unreserved',
        'get-vanilla-query-unreserved',
        'get-vanilla-ut8-query',
        'get-utf8',
        'get-space',
        'post-vanilla-query-space',
        'post-vanilla-query-nonunreserved',

        'get-slash',
        'get-slashes',
        'get-slash-dot-slash',
        'get-slash-pointless-dot',
        'get-relative',
        'get-relative-relative',
    );

    private $emarsysFixtures = array(
        'get-header-key-duplicate',
        'get-header-value-order',
        'get-port',
        'post-header-key-order',
        'post-header-value-spaces',
        'post-header-value-spaces-within-quotes',
    );

    private function processFixtures($input, $output)
    {
        $fixtures = array();
        foreach(array('aws4' => $this->amazonFixtures, 'emarsys' => $this->emarsysFixtures) as $suiteName => $suiteFixtures) {
            foreach ($suiteFixtures as $fixtureName) {
                $inputFixture = $this->fixture($suiteName, $fixtureName, $input);
                $outputFixture = $this->fixture($suiteName, $fixtureName, $output);
                $fixtures["$suiteName : $fixtureName"] = array($inputFixture, $outputFixture);
            }
        }
        return $fixtures;
    }

    /**
     * @test
     * @dataProvider StringToSignFileList
     */
    public function itShouldCreateStringToSign($canonicalRequestString, $expectedStringToSign)
    {
        $credentialScope = 'us-east-1/host/aws4_request';
        $actualStringToSign = EscherSigner::createStringToSign(
            $credentialScope,
            $canonicalRequestString,
            new DateTime("09 Sep 2011 23:36:00", new DateTimeZone('GMT')),
            'sha256',
            'AWS4'
        );
        $this->assertEquals($expectedStringToSign, $actualStringToSign);
    }

    public function stringToSignFileList()
    {
        return $this->processFixtures('creq', 'sts');
    }

    /**
     * @test
     * @dataProvider headerFileList
     */
    public function itShouldBuildAuthHeader($stringToSign, $expectedAuthHeaders)
    {
        $matches = EscherAuthElements::parseAuthHeader($expectedAuthHeaders, 'AWS4');

        list($accessKey, $credentialScope) = explode("/", $matches['Credentials'], 2);

        $signingKey = $this->hex2bin("e220a8ee99f059729066fd06efe5c0f949d6aa8973360d189dd0e0eddd7a9596");
        $actualAuthHeader = EscherSigner::createAuthHeader(
            EscherSigner::createSignature($stringToSign, $signingKey, $matches['Algorithm']),
            $credentialScope,
            $matches['SignedHeaders'],
            $matches['Algorithm'],
            'AWS4',
            $accessKey
        );
        $this->assertEquals($expectedAuthHeaders, $actualAuthHeader);
    }

    public function headerFileList()
    {
        return $this->processFixtures('sts', 'authz');
    }

    /**
     * @test
     * @dataProvider canonicalizeFixtures
     */
    public function itShouldCalculateCanonicalRequest($rawRequest, $canonicalRequestString)
    {
        list($method, $requestUri, $body, $headerLines) = $this->parseRawRequest($rawRequest);
        $headersToSign = array();
        foreach ($headerLines as $headerLine) {
            if ("\t" != $headerLine{0} && false !== strpos($headerLine, ':')) {
                list ($headerKey) = explode(':', $headerLine, 2);
                $headersToSign[]= $headerKey;
            }
        }
        $canonicalizedRequest = EscherRequestCanonicalizer::canonicalize(
            $method,
            $requestUri,
            $body,
            implode("\n", $headerLines),
            array_unique(array_map('strtolower', $headersToSign)),
            'sha256'
        );
        $this->assertEquals($canonicalRequestString, $canonicalizedRequest);
    }

    public function canonicalizeFixtures()
    {
        return $this->processFixtures('req', 'creq');
    }

    private function parseRawRequest($content)
    {
        $rows = explode("\n", $content);
        list($method, $requestUri) = explode(' ', $rows[0]);

        return array(
            $method,
            $requestUri,
            $rows[count($rows) - 1],
            array_slice($rows, 1, -2),
        );
    }

    private function hex2bin($hexstr)
    {
        if (version_compare(PHP_VERSION, '5.4') == 1) {
            return hex2bin($hexstr);
        }
        $n = strlen($hexstr);
        $sbin="";
        $i=0;
        while($i<$n)
        {
            $a =substr($hexstr,$i,2);
            $c = pack("H*",$a);
            if ($i==0){$sbin=$c;}
            else {$sbin.=$c;}
            $i+=2;
        }
        return $sbin;
    }

    private function fixture($suiteName, $fixtureName, $extension)
    {
        return file_get_contents(dirname(__FILE__) . "/../fixtures/{$suiteName}_testsuite/{$fixtureName}.{$extension}");
    }
}
