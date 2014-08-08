<?php

class AsrFacade
{
    const SHA256 = 'sha256';
    const ACCEPTABLE_REQUEST_TIME_DIFFERENCE = 900;
    const DEFAULT_AUTH_HEADER_KEY = 'X-Ems-Auth';
    const DATE_FORMAT = self::ISO8601;
    const ISO8601 = 'Ymd\THis\Z';

    public static function createClient($secretKey, $accessKeyId, $region, $service, $requestType)
    {
        return new AsrClient(new AsrParty($region, $service, $requestType), $secretKey, $accessKeyId, 'sha256', 'EMS');
    }

    public static function createServer($region, $service, $requestType, $keyDB)
    {
        $keyDB = $keyDB instanceof ArrayAccess ? $keyDB : (is_array($keyDB) ? new ArrayObject($keyDB) : new ArrayObject(array()));
        return new AsrServer(new AsrParty($region, $service, $requestType), $keyDB, 'EMS');
    }
}

class AsrParty
{
    protected $region;
    protected $service;
    protected $requestType;

    public function __construct($region, $service, $requestType)
    {
        $this->region = $region;
        $this->service = $service;
        $this->requestType = $requestType;
    }

    public function toArray()
    {
        return array($this->region, $this->service, $this->requestType);
    }

    public function getRegion()
    {
        return $this->region;
    }

    public function getService()
    {
        return $this->service;
    }

    public function getRequestType()
    {
        return $this->requestType;
    }
}

class AsrClient
{
    private $party;
    private $secretKey;
    private $accessKeyId;

    private $vendorPrefix;
    private $hashAlgo;

    public function __construct(AsrParty $party, $secretKey, $accessKeyId, $hashAlgo = "sha256", $vendorPrefix = "EMS")
    {
        $this->party        = $party;
        $this->secretKey    = $secretKey;
        $this->accessKeyId  = $accessKeyId;

        $this->vendorPrefix = $vendorPrefix;
        $this->hashAlgo     = $hashAlgo;
    }

    public function getSignedHeaders($method, $url, $requestBody, $headerList, $headersToSign, $date = null, $authHeaderKey = "X-Ems-Auth")
    {
        if(empty($date))
        {
            $date = new DateTime('now', new DateTimeZone('UTC'));
        }

        list($host, $path, $query) = $this->parseUrl($url);

        $request = array(
            'method'  => $method,
            'path'    => $path,
            'query'   => $query,
            'headers' => $headerList,
            'body'    => $requestBody,
        );
        $credentialScope = implode("/", $this->party->toArray());
        $credentialScopeWithDatePrefix = $date->format("Ymd") . "/" .  $credentialScope;
        $dateHeaderKey = "X-" . ucfirst(strtolower($this->vendorPrefix)) . "-Date";
        $headerList += array('Host' => $host, $dateHeaderKey => $date->format('Ymd\THis\Z'));

        $canonizedRequest = AsrRequestCanonizer::canonize(
            $request,
            $headersToSign,
            $this->hashAlgo
        );

        $stringToSign = AsrSigner::createStringToSign(
            $credentialScope,
            $canonizedRequest,
            $date,
            $this->hashAlgo,
            $this->vendorPrefix
        );

        $signerKey = AsrSigner::calculateSigningKey(
            $this->secretKey,
            $credentialScopeWithDatePrefix,
            $this->hashAlgo,
            $this->vendorPrefix
        );

        $authHeader = AsrSigner::createAuthHeader(
            $stringToSign,
            $signerKey,
            $this->accessKeyId,
            $credentialScopeWithDatePrefix,
            implode(";", $headersToSign),
            $this->hashAlgo,
            $this->vendorPrefix
        );

        $headerList += array($authHeaderKey => $authHeader);

        return $headerList;
    }

    private function parseUrl($url)
    {
        $urlParts = parse_url($url);
        $host = $urlParts['host'];
        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';
        return array($host, $path, $query);
    }
}

class AsrServer
{
    /**
     * @var AsrParty
     */
    private $party;

    /**
     * @var ArrayAccess
     */
    private $keyDB;

    private $vendorPrefix;

    public function __construct(AsrParty $party, ArrayAccess $keyDB, $vendorPrefix)
    {
        $this->party        = $party;
        $this->keyDB        = $keyDB;
        $this->vendorPrefix = $vendorPrefix;
    }

    public function validateRequest(array $serverVars = null, $requestBody = null, $authHeaderKey = AsrFacade::DEFAULT_AUTH_HEADER_KEY)
    {
        $serverVars = null === $serverVars ? $_SERVER : $serverVars;
        $requestBody = null === $requestBody ? $this->fetchRequestBodyFor($serverVars['REQUEST_METHOD']) : $requestBody;

        $helper = new AsrRequestHelper($serverVars, $requestBody, $authHeaderKey);
        $authHeader = $helper->getAuthHeaders();

        $this->validateHashAlgo($authHeader);
        $this->validateDates($authHeader, $helper);
        $this->validateHost($authHeader, $helper);
        $this->validateCredentials($authHeader);
        $this->validateSignature($authHeader, $helper);
    }

    private function validateDates(AsrAuthHeader $authHeader, AsrRequestHelper $helper)
    {
        if (!$this->checkDates($authHeader->getLongDate(), $authHeader->getShortDate(), $helper->getTimeStamp())) {
            throw new AsrException('One of the date headers are invalid');
        }
    }

    private function validateHost(AsrAuthHeader $authHeader, AsrRequestHelper $helper)
    {
        if($helper->getServerName() !== $authHeader->getHost()) {
            throw new AsrException('The host header does not match.');
        }
    }

    private function checkDates($dateTime, $shortDate, $serverTime)
    {
        //TODO: validate date format
        return substr($dateTime, 0, 8) == $shortDate
        && abs($serverTime - strtotime($dateTime)) < AsrFacade::ACCEPTABLE_REQUEST_TIME_DIFFERENCE;
    }

    private function validateCredentials(AsrAuthHeader $authHeader)
    {
        if (!$this->checkCredentials($authHeader->getRegion(), $authHeader->getService(), $authHeader->getRequestType())) {
            throw new AsrException('Invalid credentials');
        }
    }

    private function checkCredentials($region, $service, $requestType)
    {
        return $region == $this->party->getRegion()
        && $service == $this->party->getService()
        && $requestType == $this->party->getRequestType();
    }

    private function validateSignature(AsrAuthHeader $authHeaderOfCurrentRequest, AsrRequestHelper $helper)
    {
        $currentRequest = $helper->createRequest();
        $secret = $this->lookupSecretKey($authHeaderOfCurrentRequest->getAccessKeyId());
        $key = $authHeaderOfCurrentRequest->getAccessKeyId();
        $client = new AsrClient($this->party, $secret, $key, $authHeaderOfCurrentRequest->getAlgorithm(), $this->vendorPrefix);

        $requestHeaders = $helper->getHeaderList();

        $dateOfCurrentRequest = new DateTime(
            $requestHeaders["x-" . strtolower($this->vendorPrefix) . "-date"],
            new DateTimeZone("UTC")
        );

        $signedHeaderKeys = $authHeaderOfCurrentRequest->getSignedHeaders();

        $headers = array();
        foreach ($requestHeaders as $key => $value) {
            if (in_array($key, $signedHeaderKeys)) {
                $headers[$key] = $value;
            }
        }

        $signedHeaders = $client->getSignedHeaders(
            $currentRequest->getMethod(),
            $helper->getCurrentUrl(),
            $currentRequest->getBody(),
            $headers,
            $signedHeaderKeys,
            $dateOfCurrentRequest,
            "X-" . ucfirst(strtolower($this->vendorPrefix)) . "-Auth"
        );

        $compareSignature = substr($signedHeaders["X-" . ucfirst(strtolower($this->vendorPrefix)) . "-Auth"], -64);

        if ($compareSignature != $authHeaderOfCurrentRequest->getSignature()) {
            throw new AsrException('The signatures do not match');
        }
    }

    private function lookupSecretKey($accessKeyId)
    {
        if (!isset($this->keyDB[$accessKeyId])) {
            throw new AsrException('Invalid access key id');
        }
        return $this->keyDB[$accessKeyId];
    }

    /**
     * php://input may contain data even though the request body is empty, e.g. in GET requests
     *
     * @param string
     * @return string
     */
    private function fetchRequestBodyFor($method)
    {
        return in_array($method, array('PUT', 'POST')) ? file_get_contents('php://input') : '';
    }

    private function validateHashAlgo(AsrAuthHeader $authHeader)
    {
        if(!in_array(strtoupper($authHeader->getAlgorithm()), array('SHA256','SHA512')))
        {
            throw new AsrException('Only SHA256 and SHA512 hash algorithms are allowed.');
        }
    }
}

class AsrRequestHelper
{
    private $serverVars;
    private $requestBody;
    private $authHeaderKey;

    public function __construct(array $serverVars, $requestBody, $authHeaderKey)
    {
        $this->serverVars = $serverVars;
        $this->requestBody = $requestBody;
        $this->authHeaderKey = $authHeaderKey;
    }

    public function createRequest()
    {
        $request = new AsrRequest($this->serverVars['REQUEST_METHOD'], $this->requestBody);
        return $request;
    }

    public function getAuthHeaders()
    {
        return AsrAuthHeader::parse($this->getHeaderList(), strtolower($this->authHeaderKey));
    }

    public function getTimeStamp()
    {
        return $this->serverVars['REQUEST_TIME'];
    }

    public function getHeaderList()
    {
        $headerList = $this->process($this->serverVars);
        $headerList['content-type'] = $this->getContentType();
        return AsrHeaders::canonicalize($headerList);
    }

    public function getCurrentUrl()
    {
        $pageURL = 'http';
        if ($this->serverVars["HTTPS"] == "on") {$pageURL .= "s";}
        $pageURL .= "://";
        if ($this->serverVars["SERVER_PORT"] != "80" && $this->serverVars["SERVER_PORT"] != "443") {
            $pageURL .= $this->serverVars["SERVER_NAME"].":".$this->serverVars["SERVER_PORT"].$this->serverVars["REQUEST_URI"];
        } else {
            $pageURL .= $this->serverVars["SERVER_NAME"].$this->serverVars["REQUEST_URI"];
        }
        return $pageURL;
    }

    private function process(array $serverVars)
    {
        $headerList = array();
        foreach ($serverVars as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $headerList[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            }
        }
        return $headerList;
    }

    private function getContentType()
    {
        return isset($this->serverVars['CONTENT_TYPE']) ? $this->serverVars['CONTENT_TYPE'] : '';
    }

    public function getServerName()
    {
        return $this->serverVars['SERVER_NAME'];
    }
}

class AsrAuthHeader
{
    /**
     * @var array
     */
    private $headerParts;

    /**
     * @var array
     */
    private $credentialParts;

    /**
     * @var string
     */
    private $dateTime;

    private $host;

    public function __construct(array $headerParts, array $credentialParts, $dateTime, $host)
    {
        $this->headerParts = $headerParts;
        $this->credentialParts = $credentialParts;
        $this->dateTime = $dateTime;
        $this->host = $host;
    }

    public static function parse(array $headerList, $authHeaderKey)
    {
        $headerList = AsrHeaders::canonicalize($headerList);
        if (!isset($headerList['x-ems-date'])) {
            throw new AsrException('The X-Ems-Date header is missing');
        }
        if (!isset($headerList['host'])) {
            throw new AsrException('The Host header is missing');
        }
        if (!isset($headerList[$authHeaderKey])) {
            throw new AsrException('The '.$authHeaderKey.' header is missing');
        }
        $matches = array();
        if (1 !== preg_match(self::regex(), $headerList[$authHeaderKey], $matches)) {
            throw new AsrException('Could not parse authorization header.');
        }
        $credentialParts = explode('/', $matches['credentials']);
        if (count($credentialParts) != 5) {
            throw new AsrException('Invalid credential scope');
        }
        return new AsrAuthHeader($matches, $credentialParts, $headerList['x-ems-date'], $headerList['host']);
    }

    private static function regex()
    {
        return '/'.
        '^EMS-HMAC-(?P<algorithm>[A-Z0-9\,]+) ' .
        'Credential=(?P<credentials>[A-Za-z0-9\/\-_]+), '.
        'SignedHeaders=(?P<signed_headers>[A-Za-z\-;]+), '.
        'Signature=(?P<signature>[0-9a-f]{64})'.
        '$/';
    }

    private function getCredentialPart($index, $name)
    {
        if (!isset($this->credentialParts[$index])) {
            throw new AsrException('Invalid credential scope in the authorization header: missing '.$name);
        }
        return $this->credentialParts[$index];
    }

    public function getAccessKeyId()
    {
        return $this->getCredentialPart(0, 'access key id');
    }

    public function getShortDate()
    {
        return $this->getCredentialPart(1, 'credential date');
    }

    public function getSignedHeaders()
    {
        return explode(';', $this->headerParts['signed_headers']);
    }

    public function getSignature()
    {
        return $this->headerParts['signature'];
    }

    public function getAlgorithm()
    {
        return $this->headerParts['algorithm'];
    }

    public function getLongDate()
    {
        return $this->dateTime;
    }

    public function getRegion()
    {
        return $this->getCredentialPart(2, 'region');
    }

    public function getService()
    {
        return $this->getCredentialPart(3, 'service');
    }

    public function getRequestType()
    {
        return $this->getCredentialPart(4, 'request type');
    }

    public function getHost()
    {
        return $this->host;
    }
}

class AsrHeaders
{
    //TODO implement according to amazon document
    public static function trimHeaderValue($value)
    {
        return trim($value);
    }

    public static function canonicalize($headerList)
    {
        $result = array_combine(
            array_map('strtolower', array_keys($headerList)),
            array_map(array('AsrHeaders', 'trimHeaderValue'), array_values($headerList))
        );
        ksort($result);
        return $result;
    }
}

class AsrRequest
{
    private $method;
    private $requestBody;

    public function __construct($method, $requestBody)
    {
        $this->method = $method;
        $this->requestBody = $requestBody;
    }

    public function getMethod()
    {
        return $this->method;
    }

    public function getBody()
    {
        return $this->requestBody;
    }
}

class AsrException extends Exception
{
}

class AsrRequestCanonizer
{
    public static function canonize($requestArray, $headersToSign, $hashAlgo = "sha256")
    {
        $lines = array();
        $lines[] = strtoupper($requestArray['method']);
        $lines[] = self::normalizePath($requestArray['path']);
        $lines[] = self::urlEncodeQueryString($requestArray['query']);

        $lines = array_merge($lines, self::addHeaderLines($requestArray, $headersToSign));

        $lines[] = '';
        $lines[] = implode(";", $headersToSign);

        $lines[] = hash($hashAlgo, $requestArray['body']);

        return implode("\n", $lines);
    }

    public static function urlEncodeQueryString($query)
    {
        if (empty($query)) return "";
        $pairs = explode("&", $query);
        $encodedParts = array();

        foreach ($pairs as $pair){
            $keyValues = explode("=", $pair);
            if (strpos($keyValues[0], " ") !== false) {
                $keyValues[0] = substr($keyValues[0], 0, strpos($keyValues[0], " "));
                $keyValues[1] = "";
            }
            $encodedParts[] = implode("=",array(
                rawurlencode($keyValues[0]),
                rawurlencode($keyValues[1]),
            ));
        }
        sort($encodedParts);
        return implode("&", $encodedParts);
    }

    private static function normalizePath($path)
    {
        $path = explode('/', $path);
        $keys = array_keys($path, '..');

        foreach($keys as $keypos => $key)
        {
            array_splice($path, $key - ($keypos * 2 + 1), 2);
        }

        $path = implode('/', $path);
        $path = str_replace('./', '', $path);

        $path = str_replace("//", "/", $path);

        if (empty($path)) return "/";
        return $path;
    }

    /**
     * @param $requestArray
     * @param $headersToSign
     * @internal param $lines
     * @return array
     */
    private static function addHeaderLines($requestArray, $headersToSign)
    {
        $elements = array();
        foreach ($requestArray['headers'] as $key => $value) {
            if (!in_array(strtolower($key), $headersToSign)) continue;
            $keyInLowercase = strtolower($key);
            if (is_array($value)) {
                sort($value);
                $value = implode(',', $value);
            }
            $elements[] = $keyInLowercase . ":" . trim($value);
        }
        sort($elements);
        return $elements;
    }
}

class AsrSigner
{
    public static function createStringToSign(
        $credentialScope,
        $canonicalRequestString,
        DateTime $date,
        $hashAlgo,
        $vendorPrefix
    ) {
        $date->setTimezone(new DateTimeZone("UTC"));
        $formattedDate = $date->format('Ymd\THis\Z');
        $scope = substr($formattedDate,0, 8) . "/" . $credentialScope . "/" . strtolower($vendorPrefix) . "_request";
        $lines = array();
        $lines[] = $vendorPrefix . "-HMAC-" . strtoupper($hashAlgo);
        $lines[] = $formattedDate;
        $lines[] = $scope;
        $lines[] = hash($hashAlgo, $canonicalRequestString);
        return implode("\n", $lines);
    }

    public static function calculateSigningKey(
        $secret,
        $credentialScope,
        $hashAlgo,
        $vendorPrefix
    ) {
        $key = $vendorPrefix . $secret;
        $credentials = explode("/", $credentialScope);
        foreach ($credentials as $data) {
            $key = hash_hmac($hashAlgo, $data, $key, true);
        }
        return $key;
    }

    public static function createAuthHeader(
        $stringToSign,
        $signerKey,
        $accessKey,
        $credentialScope,
        $signedHeaders,
        $hashAlgo,
        $vendorPrefix
    ) {
        return $vendorPrefix . "-HMAC-" . strtoupper($hashAlgo)
        . " Credential="
        . $accessKey . "/"
        . $credentialScope
        . ", SignedHeaders=" . $signedHeaders
        . ", Signature=" . hash_hmac($hashAlgo, $stringToSign, $signerKey);
    }
}
