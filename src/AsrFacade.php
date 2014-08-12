<?php

class AsrFacade
{
    const DEFAULT_HASH_ALGORITHM = 'sha256';
    const ACCEPTABLE_REQUEST_TIME_DIFFERENCE = 900;
    const DEFAULT_AUTH_HEADER_KEY = 'X-Ems-Auth';
    const DATE_FORMAT = self::ISO8601;
    const ISO8601 = 'Ymd\THis\Z';

    public static function createClient($secretKey, $accessKeyId, $region, $service, $requestType)
    {
        return new AsrClient(new AsrParty($region, $service, $requestType), $secretKey, $accessKeyId, self::DEFAULT_HASH_ALGORITHM, 'EMS');
    }

    public static function createServer($region, $service, $requestType, $keyDB)
    {
        $keyDB = $keyDB instanceof ArrayAccess ? $keyDB : (is_array($keyDB) ? new ArrayObject($keyDB) : new ArrayObject(array()));
        return new AsrServer(new AsrParty($region, $service, $requestType), $keyDB, 'EMS');
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

    public function getSignedHeaders(
        $method,
        $url,
        $requestBody,
        $headerList = array(),
        $headersToSign = array('host', 'x-ems-date'),
        $date = null,
        $authHeaderKey = "X-Ems-Auth"
    )
    {
        if(empty($date))
        {
            $date = new DateTime('now', new DateTimeZone('UTC'));
        }

        list($host, $path, $query) = $this->parseUrl($url);

        $headerList += $this->mandatoryHeaders($date, $host);

        $authHeader = $this->calculateAuthHeader($headersToSign, $date, array(
            'method'  => $method,
            'path'    => $path,
            'query'   => $query,
            'headers' => $headerList,
            'body'    => $requestBody,
        ));

        $headerList += array($authHeaderKey => $authHeader);

        return $headerList;
    }

    public function getSignature(
        $method,
        $url,
        $requestBody,
        $headerList = array(),
        $headersToSign = array('host', 'x-ems-date'),
        $date = null
    )
    {
        list($host, $path, $query) = $this->parseUrl($url);

        return $this->calculateSignature($headersToSign, $date, array(
            'method'  => $method,
            'path'    => $path,
            'query'   => $query,
            'headers' => $headerList,
            'body'    => $requestBody,
        ));
    }

    private function parseUrl($url)
    {
        $urlParts = parse_url($url);
        $host = $urlParts['host'];
        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';
        return array($host, $path, $query);
    }

    /**
     * @return string
     */
    private function credentialScope()
    {
        return implode("/", $this->party->toArray());
    }

    /**
     * @param $date
     * @return string
     */
    private function fullCredentialScope(DateTime $date)
    {
        return $date->format("Ymd") . "/" . $this->credentialScope();
    }

    /**
     * @return string
     */
    private function dateHeaderKey()
    {
        return "X-" . ucfirst(strtolower($this->vendorPrefix)) . "-Date";
    }

    /**
     * @param $date
     * @param $host
     * @return array
     */
    private function mandatoryHeaders(DateTime $date, $host)
    {
        return array('Host' => $host, $this->dateHeaderKey() => $date->format('Ymd\THis\Z'));
    }

    private function calculateAuthHeader($headersToSign, $date, $request)
    {
        $authHeader = AsrSigner::createAuthHeader(
            $this->calculateSignature($headersToSign, $date, $request),
            $this->fullCredentialScope($date),
            implode(";", $headersToSign),
            $this->hashAlgo,
            $this->vendorPrefix,
            $this->accessKeyId
        );
        return $authHeader;
    }

    private function calculateSignature($headersToSign, $date, $request)
    {
        $canonizedRequest = AsrRequestCanonizer::canonize(
            $request,
            $headersToSign,
            $this->hashAlgo
        );

        $stringToSign = AsrSigner::createStringToSign(
            $this->credentialScope(),
            $canonizedRequest,
            $date,
            $this->hashAlgo,
            $this->vendorPrefix
        );

        $signerKey = AsrSigner::calculateSigningKey(
            $this->secretKey,
            $this->fullCredentialScope($date),
            $this->hashAlgo,
            $this->vendorPrefix
        );

        $signature = AsrSigner::createSignature(
            $stringToSign,
            $signerKey,
            $this->hashAlgo
        );
        return $signature;
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
        return preg_match('/^\d{8}T\d{6}Z$/', $dateTime) && substr($dateTime, 0, 8) == $shortDate
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

        $compareSignature = $client->getSignature(
            $helper->getRequestMethod(), $helper->getCurrentUrl(), $helper->getRequestBody(), $headers, $signedHeaderKeys, $dateOfCurrentRequest
        );

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

    public function getRequestMethod()
    {
        return $this->serverVars['REQUEST_METHOD'];
    }

    public function getRequestBody()
    {
        return $this->requestBody;
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
        return $headerList;
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
        $headerList = self::keysToLower($headerList);
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

    private static function keysToLower($headerList)
    {
        $result = array_combine(
            array_map('strtolower', array_keys($headerList)),
            array_values($headerList)
        );
        return $result;
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
        $signature, $credentialScope, $signedHeaders, $hashAlgo, $vendorPrefix, $accessKey
    ) {
        return $vendorPrefix . "-HMAC-" . strtoupper($hashAlgo)
        . " Credential="
        . $accessKey . "/"
        . $credentialScope
        . ", SignedHeaders=" . $signedHeaders
        . ", Signature=" . $signature;
    }

    public static function createSignature($stringToSign, $signerKey, $hashAlgo)
    {
        return hash_hmac($hashAlgo, $stringToSign, $signerKey);
    }
}
