<?php

class AsrFacade
{
    const SHA256 = 'sha256';
    // TODO: properly document (http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html)
    const ACCEPTABLE_REQUEST_TIME_DIFFERENCE = 900;
    const DEFAULT_AUTH_HEADER_KEY = 'X-Amz-Auth';
    const AMAZON_DATE_FORMAT = self::ISO8601;
    const ISO8601 = 'Ymd\THis\Z';

    public static function createClient($secretKey, $accessKeyId, $region, $service, $requestType)
    {
        return new AsrClient(new AsrParty($region, $service, $requestType), $secretKey, $accessKeyId);
    }

    public static function createServer($region, $service, $requestType, $keyDB)
    {
        $keyDB = $keyDB instanceof ArrayAccess ? $keyDB : (is_array($keyDB) ? new ArrayObject($keyDB) : array());
        return new AsrServer(new AsrParty($region, $service, $requestType), $keyDB);
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

    public function __construct(AsrParty $party, $secretKey, $accessKeyId)
    {
        $this->party = $party;
        $this->secretKey = $secretKey;
        $this->accessKeyId = $accessKeyId;
    }

    public function signRequest($method, $url, $requestBody, $headerList, $headersToSign, $timeStamp = null, $algorithmName = AsrFacade::SHA256, $authHeaderKey = AsrFacade::DEFAULT_AUTH_HEADER_KEY)
    {
        list($host, $path, $query) = $this->parseUrl($url);
        $request = new AsrRequest($method, $path, $query, $requestBody);
        $timeStamp = $timeStamp ? $timeStamp : $_SERVER['REQUEST_TIME'];
        $amazonDateTime = $this->format($timeStamp);

        $headerList += array('Host' => $host, 'X-Amz-Date' => $amazonDateTime);
        $headersToSign = array_merge($headersToSign, array('host', 'x-amz-date'));
        // TODO: handle port in the host headers
        $signer = new AsrSigner(
            AsrHashAlgorithm::create($algorithmName),
            new AsrCredentials($this->accessKeyId, $this->party),
            AsrHeaders::createFrom($headerList, $headersToSign),
            $request
        );
        return $signer->buildAuthHeaders($this->secretKey, $authHeaderKey, $amazonDateTime);
    }

    /**
     * @param $url
     * @return array
     */
    private function parseUrl($url)
    {
        $urlParts = parse_url($url);
        $host = $urlParts['host'];
        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';
        return array($host, $path, $query);
    }

    private function format($timeStamp)
    {
        $result = new DateTime();
        $result->setTimezone(new DateTimeZone('UTC'));
        $result->setTimestamp($timeStamp);
        return $result->format(AsrFacade::AMAZON_DATE_FORMAT);
    }
}

interface AsrRequestValidator
{
    public function checkDates($amazonDateTime, $amazonShortDate, $serverTime);
    public function checkCredentials($region, $service, $requestType);
}

class AsrServer implements AsrRequestValidator
{
    /**
     * @var AsrParty
     */
    private $party;

    /**
     * @var ArrayAccess
     */
    private $keyDB;

    public function __construct(AsrParty $party, ArrayAccess $keyDB)
    {
        $this->party = $party;
        $this->keyDB = $keyDB;
    }

    public function validateRequest(array $serverVars = null, $requestBody = null, $authHeaderKey = AsrFacade::DEFAULT_AUTH_HEADER_KEY)
    {
        $helper = $this->createRequestHelper($serverVars, $requestBody, $authHeaderKey);
        $authHeader = $helper->getAuthHeaders();

        $authHeader->validateDates($this, $helper->getTimeStamp());
        $authHeader->validateCredentials($this);

        $accessKeyId = $authHeader->getAccessKeyId();

        $amazonDateTime = $authHeader->getLongDate();
        $signer = new AsrSigner(
            $authHeader->createAlgorithm(),
            $authHeader->createCredentials(),
            AsrHeaders::createFrom($helper->getHeaderList(), $authHeader->getSignedHeaders()),
            $helper->createRequest()
        );
        $signature = $signer->calculateSignature($this->lookupSecretKey($accessKeyId), $amazonDateTime);

        if ($signature != $authHeader->getSignature()) {
            throw new AsrException('The signatures do not match');
        }
    }

    public function checkDates($amazonDateTime, $amazonShortDate, $serverTime)
    {
        //TODO: validate date format
        return substr($amazonDateTime, 0, 8) == $amazonShortDate
        && abs($serverTime - strtotime($amazonDateTime)) < AsrFacade::ACCEPTABLE_REQUEST_TIME_DIFFERENCE;
    }

    /**
     * @param string $accessKeyId
     * @return string
     * @throws AsrException
     */
    public function lookupSecretKey($accessKeyId)
    {
        if (!isset($this->keyDB[$accessKeyId])) {
            throw new AsrException('Invalid access key id');
        }
        return $this->keyDB[$accessKeyId];
    }

    public function checkCredentials($region, $service, $requestType)
    {
        return $region == $this->party->getRegion()
            && $service == $this->party->getService()
            && $requestType == $this->party->getRequestType();
    }

    /**
     * @param array $serverVars
     * @param array $requestBody
     * @param string $authHeaderKey
     * @return AsrRequestHelper
     */
    private function createRequestHelper(array $serverVars = null, $requestBody = null, $authHeaderKey = AsrFacade::DEFAULT_AUTH_HEADER_KEY)
    {
        $serverVars = null === $serverVars ? $_SERVER : $serverVars;
        $requestBody = null === $requestBody ? file_get_contents('php://input') : $requestBody;
        return new AsrRequestHelper($serverVars, $requestBody, $authHeaderKey);
    }}

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
        list ($path, $query) = array_pad(explode('?', $this->serverVars['REQUEST_URI'], 2), 2, '');
        $request = new AsrRequest($this->serverVars['REQUEST_METHOD'], $path, $query, $this->requestBody);
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

    public function getHost()
    {
        return $this->serverVars['HTTP_HOST'];
    }

    public function getHeaderList()
    {
        $headerList = array();
        foreach ($this->serverVars as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $headerList[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            }
        }
        $headerList['content-type'] = $this->getContentType();
        return AsrHeaders::canonicalize($headerList);
    }

    protected function getContentType()
    {
        return isset($this->serverVars['CONTENT_TYPE']) ? $this->serverVars['CONTENT_TYPE'] : '';
    }
}

class AsrSigner
{
    /**
     * @var AsrHashAlgorithm
     */
    private $algorithm;

    /**
     * @var AsrCredentials
     */
    private $credentials;

    /**
     * @var AsrHeaders
     */
    private $headers;

    /**
     * @var AsrRequest
     */
    private $request;

    public function __construct(AsrHashAlgorithm $algorithm, AsrCredentials $credentials, AsrHeaders $headers, AsrRequest $request)
    {
        $this->algorithm = $algorithm;
        $this->credentials = $credentials;
        $this->headers = $headers;
        $this->request = $request;
    }

    /**
     * @param string $secretKey
     * @param string $amazonDateTime
     * @return string
     */
    public function calculateSignature($secretKey, $amazonDateTime)
    {
        $requestBodyHash      = $this->algorithm->hash($this->request->getBody());
        $canonicalizedRequest = $this->canonicalizeRequest($requestBodyHash);
        $canonicalHash        = $this->algorithm->hash($canonicalizedRequest);
        $stringToSign         = $this->generateStringToSign($canonicalHash, $amazonDateTime);
        $signingKey           = $this->generateSigningKey($secretKey, $amazonDateTime);
        $signature            = $this->algorithm->hmac($stringToSign, $signingKey, false);
        return $signature;
    }

    public function buildAuthHeaders($secretKey, $authHeaderKey, $amazonDateTime)
    {
        return array('X-Amz-Date' => $amazonDateTime) + AsrAuthHeader::build(
            $this->algorithm->toHeaderString(),
            $this->credentials->toScopeString($amazonDateTime),
            $this->headers->toHeaderString(),
            $this->calculateSignature($secretKey, $amazonDateTime),
            $authHeaderKey
        );
    }

    private function generateStringToSign($canonicalHash, $amazonDateTime)
    {
        return implode("\n", array(
            $this->algorithm->toHeaderString(),
            $amazonDateTime,
            $this->credentials->scopeToSign($amazonDateTime),
            $canonicalHash
        ));
    }

    private function generateSigningKey($secretKey, $amazonDateTime)
    {
        $key = $secretKey;
        foreach ($this->credentials->toArray($amazonDateTime) as $data) {
            $key = $this->algorithm->hmac($data, $key, true);
        }
        return $key;
    }

    private function canonicalizeRequest($requestBodyHash)
    {
        $lines = array();
        $lines[] = strtoupper($this->request->getMethod());
        $lines[] = $this->request->getPath();
        $lines[] = $this->request->getQuery();
        foreach ($this->headers->collapse() as $headerLine) {
            $lines[] = $headerLine;
        }
        $lines[] = '';
        $lines[] = $this->headers->toHeaderString();
        $lines[] = $requestBodyHash;

        return implode("\n", $lines);
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
    private $amazonDateTime;

    public function __construct(array $headerParts, array $credentialParts, $amazonDateTime)
    {
        $this->headerParts = $headerParts;
        $this->credentialParts = $credentialParts;
        $this->amazonDateTime = $amazonDateTime;
    }

    public static function parse(array $headerList, $authHeaderKey)
    {
        $headerList = AsrHeaders::canonicalize($headerList);
        if (!isset($headerList['x-amz-date'])) {
            throw new AsrException('The X-Amz-Date header is missing');
        }
        if (!isset($headerList[strtolower($authHeaderKey)])) {
            throw new AsrException('The '.$authHeaderKey.' header is missing');
        }
        $matches = array();
        if (1 !== preg_match(self::regex(), $headerList[strtolower($authHeaderKey)], $matches)) {
            throw new AsrException('Could not parse authorization header.');
        }
        $credentialParts = explode('/', $matches['credentials']);
        if (count($credentialParts) != 5) {
            throw new AsrException('Invalid credential scope');
        }
        return new AsrAuthHeader($matches, $credentialParts, $headerList['x-amz-date']);
    }

    private static function regex()
    {
        return '/'.
        '^AWS4-HMAC-(?P<algorithm>[A-Z0-9\,]+) ' .
        'Credential=(?P<credentials>[A-Za-z0-9\/\-_]+), '.
        'SignedHeaders=(?P<signed_headers>[a-z\-;]+), '.
        'Signature=(?P<signature>[0-9a-f]{64})'.
        '$/';
    }

    public static function build($algorithmHeaderName, $credentialScope, $signedHeaders, $signature, $authHeaderKey)
    {
        return array($authHeaderKey => $algorithmHeaderName . ' ' .
            "Credential={$credentialScope}, " .
            "SignedHeaders={$signedHeaders}, ".
            "Signature=$signature");
    }

    private function getCredentialPart($index, $name)
    {
        if (!isset($this->credentialParts[$index])) {
            throw new AsrException('Invalid credential scope in the authorization header: missing '.$name);
        }
        return $this->credentialParts[$index];
    }

    public function createAlgorithm()
    {
        return AsrHashAlgorithm::create($this->headerParts['algorithm']);
    }

    public function createCredentials()
    {
        $party = new AsrParty($this->getRegion(), $this->getService(), $this->getRequestType());
        return new AsrCredentials($this->getAccessKeyId(), $party);
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

    public function getLongDate()
    {
        return $this->amazonDateTime;
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

    public function validateDates(AsrRequestValidator $validator, $serverTime)
    {
        if (!$validator->checkDates($this->amazonDateTime, $this->getShortDate(), $serverTime)) {
            throw new AsrException('One of the date headers are invalid');
        }
    }

    public function validateCredentials(AsrRequestValidator $validator)
    {
        if (!$validator->checkCredentials($this->getRegion(), $this->getService(), $this->getRequestType())) {
            throw new AsrException('Invalid credentials');
        }
    }
}

interface AuthHeaderPart
{
    public function toHeaderString();
}

class AsrHashAlgorithm implements AuthHeaderPart
{
    /**
     * @var string
     */
    private $algorithmName;

    /**
     * @param string $algorithmName
     */
    public function __construct($algorithmName)
    {
        $this->algorithmName = $algorithmName;
    }

    public static function create($algorithmName)
    {
        $algorithmName = strtolower($algorithmName);
        if (!in_array($algorithmName, hash_algos())) {
            throw new AsrException("Invalid algorithm: '$algorithmName'");
        }
        return new AsrHashAlgorithm($algorithmName);
    }

    public function toHeaderString()
    {
        return 'AWS4-HMAC-' . strtoupper($this->algorithmName);
    }

    public function hmac($data, $key, $raw = false)
    {
        return hash_hmac($this->algorithmName, $data, $key, $raw);
    }

    public function hash($data, $raw = false)
    {
        return hash($this->algorithmName, $data, $raw);
    }
}

class AsrCredentials
{
    /**
     * @var string
     */
    private $accessKeyId;

    /**
     * @var AsrParty
     */
    private $party;

    public function __construct($accessKeyId, AsrParty $party)
    {
        $this->accessKeyId = $accessKeyId;
        $this->party = $party;
    }

    public function toArray($amazonDateTime)
    {
        return array_merge(array(substr($amazonDateTime, 0, 8)), $this->party->toArray());
    }

    public function scopeToSign($amazonDateTime)
    {
        return implode('/', $this->toArray($amazonDateTime));
    }

    public function toScopeString($amazonDateTime)
    {
        return $this->accessKeyId . '/' . $this->scopeToSign($amazonDateTime);
    }
}

class AsrHeaders implements AuthHeaderPart
{
    /**
     * @var array
     */
    private $headerList;

    /**
     * @var array
     */
    private $headersToSign;

    public function __construct(array $headerList, array $headersToSign)
    {
        $this->headerList = $headerList;
        $this->headersToSign = $headersToSign;
    }

    public static function createFrom($headerList, array $headersToSign)
    {
        $headersToSign = array_unique(array_map('strtolower', $headersToSign));
        sort($headersToSign);
        return new AsrHeaders(self::canonicalize($headerList), $headersToSign);
    }

    //TODO implement according to amazon document
    public static function trimHeaderValue($value)
    {
        return trim($value);
    }

    public static function canonicalize($headerList)
    {
        $result = array_combine(
            array_map('strtolower', array_keys($headerList)),
            array_map('self::trimHeaderValue', array_values($headerList))
        );
        ksort($result);
        return $result;
    }

    public function toHeaderString()
    {
        return implode(';', $this->headersToSign);
    }

    public function collapse()
    {
        $headersToSign = $this->selectOnlySignedHeaders();
        return array_map(
            array($this, 'collapseLine'),
            array_keys($headersToSign),
            array_values($headersToSign)
        );
    }

    public function collapseLine($headerKey, $headerValue)
    {
        return $headerKey.':'.$headerValue;
    }

    private function selectOnlySignedHeaders()
    {
        return array_intersect_key($this->headerList, array_flip($this->headersToSign));
    }
}

class AsrRequest
{
    private $method;
    private $path;
    private $query;
    private $requestBody;

    public function __construct($method, $path, $query, $requestBody)
    {
        $this->method = $method;
        $this->path = $path;
        $this->query = $query;
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

    public function getPath()
    {
        return $this->path;
    }

    public function getQuery()
    {
        return $this->query;
    }
}

class AsrException extends Exception
{
}
