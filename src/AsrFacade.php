<?php

class AsrFacade
{
    const SHA256 = 'sha256';

    public function signRequest($secretKey, $accessKeyId, array $baseCredentials, $method, $url, $requestBody, array $headerList, array $headersToSign = array())
    {
        $urlParts = parse_url($url);
        $host     = $urlParts['host'];
        $path     = $urlParts['path'];
        $query    = isset($urlParts['query']) ? $urlParts['query'] : '';
        return AsrBuilder::create()
            ->useRequest($method, $path, $query, $requestBody)
            ->useHeaders($host, $headerList, $headersToSign)
            ->useCredentials($accessKeyId, $baseCredentials)
            ->buildAuthHeaders($secretKey);
    }

    public function checkSignature($serverDate, $host, $method, $path, $query, $requestBody, array $headerList)
    {
        $headerList      = AsrHeaders::canonicalize($headerList);
        $amazonDateTime  = $headerList['x-amz-date'];
        $authHeaderParts = AsrBuilder::parseAuthHeader($headerList['authorization']);
        $credentialParts = explode('/', $authHeaderParts['credentials']);

        $validator = new AsrValidator();
        if (!$validator->validateCredentials($credentialParts)) {
            return false;
        }
        $accessKeyId = array_shift($credentialParts);
        $amazonDate  = array_shift($credentialParts);
        if (!$validator->validateDates($serverDate, $amazonDateTime, $amazonDate)) {
            return false;
        }

        // look up secret key for access key id
        // credential scope check: {accessKeyId}/{amazonDate}/{region:eu}/{service:ac-export|suite}/ems_request
        $secretKey = 'TODO-ADD-LOOKUP';

        return AsrBuilder::create(strtotime($amazonDateTime), $authHeaderParts['algorithm'])
            ->useRequest($method, $path, $query, $requestBody)
            ->useHeaders($host, $headerList, explode(';', $authHeaderParts['signed_headers']))
            ->useCredentials($accessKeyId, $credentialParts)
            ->validate($secretKey, $authHeaderParts['signature']);
    }
}

class AsrBuilder
{
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
     * @var AsrRequest
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
        return AsrDateHelper::fromTimeStamp($timeStamp)->format(AsrDateHelper::AMAZON_DATE_FORMAT);
    }

    public static function parseAuthHeader($authHeaderString)
    {
        $matches = array();
        if (1 !== preg_match(self::regex(), $authHeaderString, $matches)) {
            throw new AsrException('Could not parse authorization header.');
        }
        return $matches;
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

    public function buildAuthHeaders($secretKey)
    {
        $signature = $this->calculateSignature($secretKey);

        return $this->dateHeader() + array('Authorization' => $this->algorithm->toHeaderString() . ' ' .
            "Credential={$this->credentials->toHeaderString($this->amazonDateTime)}, " .
            "SignedHeaders={$this->headers->toHeaderString()}, ".
            "Signature=$signature");
    }

    public function validate($secretKey, $signature)
    {
        return $signature == $this->calculateSignature($secretKey);
    }

    /**
     * @param string $accessKeyId
     * @param array $baseCredentials
     * @return AsrBuilder
     */
    public function useCredentials($accessKeyId, array $baseCredentials)
    {
        $this->credentials = new AsrCredentials($accessKeyId, $baseCredentials);
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
        $this->request = new AsrRequest($method, $path, $query, $requestBody);
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
}

class AsrSigningAlgorithm
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

    public function toScopeString($amazonDateTime)
    {
        return implode('/', $this->toArray($amazonDateTime));
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
            $this->toScopeString($amazonDateTime),
            $canonicalHash
        ));
    }

    public function toHeaderString($amazonDateTime)
    {
        return $this->accessKeyId . '/' . $this->toScopeString($amazonDateTime);
    }
}

class AsrHeaders
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

    public function get($headerKey)
    {
        return isset($this->headerList[$headerKey]) ? $this->headerList[$headerKey] : '';
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

class AsrValidator
{
    const ACCEPTABLE_TIME_INTERVAL_IN_SECONDS = 600;

    public function validateCredentials(array $credentialParts)
    {
        return 5 === count($credentialParts);
    }

    public function validateDates($serverDateString, $amazonDateTime, $amazonDate)
    {
        //TODO: validate date format
        return substr($amazonDateTime, 0, 8) == $amazonDate
            && abs(strtotime($serverDateString) - strtotime($amazonDateTime)) < self::ACCEPTABLE_TIME_INTERVAL_IN_SECONDS;
    }
}

class AsrDateHelper
{
    const AMAZON_DATE_FORMAT = self::ISO8601;
    const ISO8601 = 'Ymd\THis\Z';

    /**
     * @param $timeStamp
     * @return DateTime
     */
    private static function createDateTimeFrom($timeStamp)
    {
        $result = new DateTime();
        $result->setTimezone(new DateTimeZone('UTC'));
        $result->setTimestamp($timeStamp);
        return $result;
    }

    /**
     * @param $timeStamp
     * @return DateTime
     */
    public static function fromTimeStamp($timeStamp)
    {
        return self::createDateTimeFrom($timeStamp);
    }

    /**
     * @return DateTime
     */
    public function useRequestTime()
    {
        return self::useTimeStamp($_SERVER['REQUEST_TIME']);
    }

    /**
     * @param $dateTimeString
     * @return DateTime
     */
    public function fromAuthorizationHeader($dateTimeString)
    {
        return new DateTime($dateTimeString);
    }
}

class AsrException extends Exception
{
}
