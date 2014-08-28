<?php

class AmazonSuite extends PHPUnit_Framework_TestCase
{
    private $allFixtures = array(
        'get-header-key-duplicate',
        'get-header-value-order',
        'get-header-value-trim',
        'get-relative-relative',
        'get-relative',
        'get-slash-dot-slash',
        'get-slash-pointless-dot',
        'get-slash',
        'get-slashes',
        'get-space',
        'get-unreserved',
        'get-utf8',
        'get-vanilla-empty-query-key',
        'get-vanilla-query-order-key-case',
        'get-vanilla-query-order-key',
        'get-vanilla-query-order-value',
        'get-vanilla-query-unreserved',
        'get-vanilla-query',
        'get-vanilla-ut8-query',
        'get-vanilla',
        'post-header-key-case',
        'post-header-key-sort',
        'post-header-value-case',
        'post-vanilla-empty-query-value',
        'post-vanilla-query-nonunreserved',
        'post-vanilla-query-space',
        'post-vanilla-query',
        'post-vanilla',
        'post-x-www-form-urlencoded-parameters',
        'post-x-www-form-urlencoded',
    );

    private function processFixtures($input, $output)
    {
        $returnArray = array();
        foreach($this->allFixtures as $name) {
            $awsFixture = new AwsFixture($name);
            $returnArray[$name] = array($awsFixture->contents[$input], $awsFixture->contents[$output]);
        }
        return $returnArray;
    }

    /**
     * @test
     * @dataProvider StringToSignFileList
     */
    public function createStringToSign_Perfect_Perfect($canonicalRequestString, $expectedStringToSign)
    {
        $credentialScope = 'us-east-1/host/aws4_request';
        $actualStringToSign = AsrSigner::createStringToSign(
            $credentialScope,
            $canonicalRequestString,
            new DateTime("09 Sep 2011 23:36:00 GMT"),
            'sha256',
            'AWS4'
        );
        $this->assertEquals($expectedStringToSign, $actualStringToSign);
    }

    public function stringToSignFileList()
    {
        return $this->processFixtures('canonicalRequestString', 'stringToSign');
    }

    /**
     * @test
     * @dataProvider headerFileList
     */
    public function createAuthHeader_Perfect_Perfect($stringToSign, $expectedAuthHeaders)
    {
        $matches = AsrAuthElements::parseAuthHeader($expectedAuthHeaders, 'AWS4');

        list($accessKey, $credentialScope) = explode("/", $matches['Credentials'], 2);

        $signingKey = $this->hex2bin("e220a8ee99f059729066fd06efe5c0f949d6aa8973360d189dd0e0eddd7a9596");
        $actualAuthHeader = AsrSigner::createAuthHeader(
            AsrSigner::createSignature($stringToSign, $signingKey, $matches['Algorithm']),
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
        return $this->processFixtures('stringToSign', 'authHeader');
    }

    /**
     * @test
     * @dataProvider canonicalizeFixtures
     */
    public function canonicalize_Perfect_Perfect($rawRequest, $canonicalRequestString)
    {
        list($method, $requestUri, $body, $headerLines) = $this->parseRawRequest($rawRequest);
        $headersToSign = array();
        foreach ($headerLines as $headerLine) {
            if ("\t" != $headerLine{0} && false !== strpos($headerLine, ':')) {
                list ($headerKey) = explode(':', $headerLine, 2);
                $headersToSign[]= $headerKey;
            }
        }
        $canonicalizedRequest = AsrRequestCanonicalizer::canonicalize(
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
        return $this->processFixtures('rawRequest', 'canonicalRequestString');
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
}

class AwsFixture
{
    public $contents;

    public function __construct($name)
    {
        $this->contents = $this->load($name);
    }

    private function load($request)
    {
        $path = $this->awsFixtures();

        return array(
            "rawRequest"             => file_get_contents($path . $request . ".req"),
            "canonicalRequestString" => file_get_contents($path . $request . ".creq"),
            "stringToSign"           => file_get_contents($path . $request . ".sts"),
            "authHeader"             => file_get_contents($path . $request . ".authz"),
        );
    }

    /**
     * @return string
     */
    private function awsFixtures()
    {
        return dirname(__FILE__) . '/../fixtures/aws4_testsuite/';
    }
}
