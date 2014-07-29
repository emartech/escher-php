<?php

class AsrFacade
{
    const SHA256 = 'sha256';
    // TODO: properly document (http://s3.amazonaws.com/doc/s3-developer-guide/RESTAuthentication.html)
    const ACCEPTABLE_REQUEST_TIME_DIFFERENCE = 900;

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

    public function createCredentials($accessKeyId)
    {
        return new AsrCredentials($accessKeyId, $this->toArray());
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

    public function signRequest($method, $url, $requestBody, $headerList, $headersToSign, $timeStamp = null, $algorithmName = AsrFacade::SHA256)
    {
        list($host, $path, $query) = $this->parseUrl($url);
        return AsrBuilder::create($timeStamp, $algorithmName)
            ->useRequest($method, $path, $query, $requestBody)
            ->useHeaders($host, $headerList, $headersToSign)
            ->useCredentials($this->accessKeyId, $this->party)
            ->buildAuthHeaders($this->secretKey);
    }

    /**
     * @param $url
     * @return array
     */
    public function parseUrl($url)
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

    public function __construct(AsrParty $party, ArrayAccess $keyDB)
    {
        $this->party = $party;
        $this->keyDB = $keyDB;
    }

    public function validateRequest()
    {
        $request = AsrRequestToValidate::create();
        $authHeader = $request->getAuthHeaders();

        if (!$this->checkDates($request)) {
            throw new AsrException('One of the date headers are invalid');
        }

        // credential scope check: {accessKeyId}/{amazonDate}/{region:eu}/{service:ac-export|suite}/ems_request
        if (!$this->checkCredentials($authHeader)) {
            throw new AsrException('Invalid credentials');
        }
        $accessKeyId = $authHeader->getAccessKeyId();

        return AsrBuilder::create(strtotime($authHeader->getLongDate()), $authHeader->getAlgorithm())
            ->useRequest($request->getMethod(), $request->getPath(), $request->getQuery(), $request->getBody())
            ->useHeaders($request->getHost(), $request->getHeaderList(), $authHeader->getSignedHeaders())
            ->useCredentials($accessKeyId, $authHeader->getParty())
            ->validate($this->lookupSecretKey($accessKeyId), $authHeader->getSignature());
    }

    public function checkDates(AsrRequestToValidate $request)
    {
        $amazonDateTime = $request->getAuthHeaders()->getLongDate();
        $amazonShortDate = $request->getAuthHeaders()->getShortDate();
        //TODO: validate date format
        return substr($amazonDateTime, 0, 8) == $amazonShortDate
        && abs($request->getTimeStamp() - strtotime($amazonDateTime)) < AsrFacade::ACCEPTABLE_REQUEST_TIME_DIFFERENCE;
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

    private function checkCredentials(AsrAuthHeader $authHeader)
    {
        return $authHeader->getRegion() == $this->party->getRegion()
            && $authHeader->getService() == $this->party->getService()
            && $authHeader->getRequestType() == $this->party->getRequestType();
    }
}

class AsrRequestToValidate
{
    /**
     * @var array
     */
    private $serverVars;

    /**
     * @var array
     */
    private $headerList;

    /**
     * @var string
     */
    private $requestBody;

    /**
     * @var string
     */
    private $path;

    /**
     * @var string
     */
    private $query;

    /**
     * @param array $serverVars
     * @param array $headerList
     * @param string $path
     * @param string $query
     * @param string $requestBody
     */
    public function __construct(array $serverVars, array $headerList, $path, $query, $requestBody)
    {
        $this->serverVars  = $serverVars;
        $this->headerList  = $headerList;
        $this->path        = $path;
        $this->query       = $query;
        $this->requestBody = $requestBody;
    }

    /**
     * @param array $serverVars
     * @param string $requestBody
     * @return AsrRequestToValidate
     */
    public static function create($serverVars = null, $requestBody = null)
    {
        $serverVars = null === $serverVars ? $_SERVER : $serverVars;
        $requestBody = null === $requestBody ? file_get_contents('php://input') : $requestBody;
        $headerList = self::normalizeHeaders($serverVars);
        list ($path, $query) = array_pad(explode('?', $serverVars['REQUEST_URI'], 2), 2, '');
        return new AsrRequestToValidate($serverVars, $headerList, $path, $query, $requestBody);
    }

    /**
     * @param $serverVars
     * @return array
     */
    private static function normalizeHeaders($serverVars)
    {
        $headerList = array();
        foreach ($serverVars as $key => $value) {
            if (substr($key, 0, 4) == 'HTTP') {
                $headerList[str_replace('_', '-', substr($key, 5))] = $value;
            }
        }
        return AsrHeaders::canonicalize($headerList);
    }

    /**
     * @return array
     */
    public function getHeaderList()
    {
        return $this->headerList;
    }

    public function getTimeStamp()
    {
        return $this->serverVars['REQUEST_TIME'];
    }

    public function getHost()
    {
        return $this->headerList['host'];
    }

    public function getMethod()
    {
        return $this->serverVars['REQUEST_METHOD'];
    }

    public function getPath()
    {
        return $this->path;
    }

    public function getQuery()
    {
        return $this->query;
    }

    public function getBody()
    {
        return $this->requestBody;
    }

    public function getAuthHeaders()
    {
        return AsrAuthHeader::parse($this->headerList);
    }
}

class AsrBuilder
{
    const AMAZON_DATE_FORMAT = self::ISO8601;
    const ISO8601 = 'Ymd\THis\Z';

    /**
     * @var AsrSigningAlgorithm
     */
    private $algorithm;

    /**
     * @var string
     */
    private $amazonDateTime;

    /**
     * @var AsrCredentials
     */
    private $credentials;

    /**
     * @var AsrHeaders
     */
    private $headers;

    /**
     * @var AsrRequestToSign
     */
    private $request;

    public function __construct($amazonDateTime, AsrSigningAlgorithm $algorithm)
    {
        $this->amazonDateTime = $amazonDateTime;
        $this->algorithm = $algorithm;
    }

    public static function create($timeStamp = null, $algorithmName = AsrFacade::SHA256)
    {
        $timeStamp = $timeStamp ? $timeStamp : $_SERVER['REQUEST_TIME'];
        return new AsrBuilder(self::format($timeStamp), new AsrSigningAlgorithm(strtolower($algorithmName)));
    }

    public static function format($timeStamp)
    {
        $result = new DateTime();
        $result->setTimezone(new DateTimeZone('UTC'));
        $result->setTimestamp($timeStamp);
        return $result->format(self::AMAZON_DATE_FORMAT);
    }

    public function validate($secretKey, $signature)
    {
        return $signature == $this->calculateSignature($secretKey);
    }

    /**
     * @param string $accessKeyId
     * @param AsrParty $party
     * @return AsrBuilder
     */
    public function useCredentials($accessKeyId, AsrParty $party)
    {
        $this->credentials = new AsrCredentials($accessKeyId, $party->toArray());
        return $this;
    }

    /**
     * @param string $host
     * @param array $headerList
     * @param array $headersToSign
     * @return AsrBuilder
     */
    public function useHeaders($host, array $headerList, array $headersToSign)
    {
        $hostHeader = array('Host' => $host); //TODO; handle port
        $this->headers = AsrHeaders::createFrom($this->dateHeader() + $hostHeader + $headerList, $headersToSign);
        return $this;
    }

    /**
     * @param string $method
     * @param string $path
     * @param string $query
     * @param string $requestBody
     * @return AsrBuilder
     */
    public function useRequest($method, $path, $query, $requestBody)
    {
        $this->request = new AsrRequestToSign($method, $path, $query, $requestBody);
        return $this;
    }

    /**
     * @return array
     */
    public function dateHeader()
    {
        return array('X-Amz-Date' => $this->amazonDateTime);
    }

    /**
     * @param $secretKey
     * @return string
     */
    public function calculateSignature($secretKey)
    {
        $canonicalHash = $this->request->canonicalizeUsing($this->algorithm, $this->headers);
        $stringToSign = $this->credentials->generateStringToSignUsing($this->algorithm, $canonicalHash, $this->amazonDateTime);
        $signingKey = $this->credentials->generateSigningKeyUsing($this->algorithm, $secretKey, $this->amazonDateTime);
        return $this->algorithm->hmac($stringToSign, $signingKey, false);
    }

    public function buildAuthHeaders($secretKey)
    {
        return $this->dateHeader() + AsrAuthHeader::build(
            $this->algorithm,
            $this->credentials->createScope($this->amazonDateTime),
            $this->headers,
            $this->calculateSignature($secretKey)
        );
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

    public static function parse(array $headerList)
    {
        $headerList = AsrHeaders::canonicalize($headerList);
        if (!isset($headerList['x-amz-date'])) {
            throw new AsrException('The X-Amz-Date header is missing');
        }
        if (!isset($headerList['authorization'])) {
            throw new AsrException('The Authorization header is missing');
        }
        $matches = array();
        if (1 !== preg_match(self::regex(), $headerList['authorization'], $matches)) {
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

    public static function build(AsrSigningAlgorithm $algorithm, AsrCredentialScope $credentialScope, AsrHeaders $headers, $signature)
    {
        return array('Authorization' => $algorithm->toHeaderString() . ' ' .
            "Credential={$credentialScope->toHeaderString()}, " .
            "SignedHeaders={$headers->toHeaderString()}, ".
            "Signature=$signature");
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

    public function getAlgorithm()
    {
        return $this->headerParts['algorithm'];
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
        return $this->getCredentialPart(3, 'region');
    }

    public function getService()
    {
        return $this->getCredentialPart(4, 'service');
    }

    public function getRequestType()
    {
        return $this->getCredentialPart(4, 'request type');
    }

    public function getParty()
    {
        return new AsrParty($this->getRegion(), $this->getService(), $this->getRequestType());
    }
}

interface AuthHeaderPart
{
    public function toHeaderString();
}

class AsrSigningAlgorithm implements AuthHeaderPart
{
    /**
     * @var string
     */
    private $algorithm;

    /**
     * @param string $algorithm
     * @throws AsrException
     */
    public function __construct($algorithm)
    {
        if (!in_array($algorithm, hash_algos())) {
            throw new AsrException("Invalid algorithm: '$algorithm'");
        }
        $this->algorithm = $algorithm;
    }

    public function toHeaderString()
    {
        return 'AWS4-HMAC-' . strtoupper($this->algorithm);
    }

    public function hmac($data, $key, $raw = false)
    {
        return hash_hmac($this->algorithm, $data, $key, $raw);
    }

    public function hash($data, $raw = false)
    {
        return hash($this->algorithm, $data, $raw);
    }
}

class AsrCredentials
{
    /**
     * @var string
     */
    private $accessKeyId;

    /**
     * @var array
     */
    private $parts;

    public function __construct($accessKeyId, array $parts)
    {
        if (count($parts) != 3) {
            throw new AsrException('Credentials should consist of exactly 3 parts');
        }
        $this->accessKeyId = $accessKeyId;
        $this->parts = $parts;
    }

    public function toArray($amazonDateTime)
    {
        return array_merge(array($this->shorten($amazonDateTime)), $this->parts);
    }

    private function shorten($amazonDateTime)
    {
        return substr($amazonDateTime, 0, 8);
    }

    public function generateSigningKeyUsing(AsrSigningAlgorithm $algorithm, $secretKey, $amazonDateTime)
    {
        $key = $secretKey;
        foreach ($this->toArray($amazonDateTime) as $data) {
            $key = $algorithm->hmac($data, $key, true);
        }
        return $key;
    }

    public function generateStringToSignUsing(AsrSigningAlgorithm $algorithm, $canonicalHash, $amazonDateTime)
    {
        return implode("\n", array(
            $algorithm->toHeaderString(),
            $amazonDateTime,
            $this->scopeToSign($amazonDateTime),
            $canonicalHash
        ));
    }

    /**
     * @param $amazonDateTime
     * @return string
     */
    public function scopeToSign($amazonDateTime)
    {
        return implode('/', $this->toArray($amazonDateTime));
    }

    public function toScopeString($amazonDateTime)
    {
        return $this->accessKeyId . '/' . $this->scopeToSign($amazonDateTime);
    }

    public function createScope($amazonDateTime)
    {
        return new AsrCredentialScope($this, $amazonDateTime);
    }
}

class AsrCredentialScope implements AuthHeaderPart
{
    /**
     * @var AsrCredentials
     */
    private $credentials;

    /**
     * @var string
     */
    private $amazonDateTime;

    public function __construct(AsrCredentials $credentials, $amazonShortDate)
    {
        $this->credentials = $credentials;
        $this->amazonDateTime = $amazonShortDate;
    }

    /**
     * @return string
     */
    public function toHeaderString()
    {
        return $this->credentials->toScopeString($this->amazonDateTime);
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

    public static function createFrom($headerList, $headersToSign = array())
    {
        $headersToSign = array_unique(array_merge(array_map('strtolower', $headersToSign), array('host', 'x-amz-date')));

        sort($headersToSign);
        ksort($headerList);
        return new AsrHeaders(self::canonicalize($headerList), $headersToSign);
    }

    public static function trimHeaderValue($value)
    {
        return trim($value);
    }

    public static function canonicalize($headerList)
    {
        return array_combine(
            array_map('strtolower', array_keys($headerList)),
            array_map('self::trimHeaderValue', array_values($headerList))
        );
    }

    public function toHeaderString()
    {
        return implode(';', $this->headersToSign);
    }

    public function collapse()
    {
        $headersToSign = array_intersect_key($this->headerList, array_flip($this->headersToSign));
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

    public function getSignedHeaders()
    {
        return $this->headersToSign;
    }
}

class AsrRequestToSign
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

    /**
     * @param AsrSigningAlgorithm $algorithm
     * @param AsrHeaders $headers
     * @return string
     */
    public function canonicalizeUsing(AsrSigningAlgorithm $algorithm, AsrHeaders $headers)
    {
        $lines = array();
        $lines[] = strtoupper($this->method);
        $lines[] = $this->path;
        $lines[] = $this->query;
        foreach ($headers->collapse() as $headerLine) {
            $lines[] = $headerLine;
        }
        $lines[] = '';
        $lines[] = $headers->toHeaderString();
        $lines[] = $algorithm->hash($this->requestBody);

        return $algorithm->hash(implode("\n", $lines));
    }
}

class AsrException extends Exception
{
}
