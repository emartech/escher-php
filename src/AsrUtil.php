<?php

class AsrUtil
{
    const SHA256 = 'sha256';

    public function signRequest($algorithmName, $secretKey, $accessKeyId, array $baseCredentials, $fullDate, $method, $url, $requestBody, array $headerList, array $headersToSign = array())
    {
        $urlParts = parse_url($url);
        $host     = $urlParts['host'];
        $path     = $urlParts['path'];
        $query    = isset($urlParts['query']) ? $urlParts['query'] : '';
        return AsrAuthHeader::create()
            ->useAlgorithm($algorithmName)
            ->useTimestamp(strtotime($fullDate))
            ->useCredentials($accessKeyId, $baseCredentials)
            ->useHeaders($host, $headerList, $headersToSign)
            ->useRequest($method, $path, $query, $requestBody)
            ->build($secretKey);
    }

    public function checkSignature($serverDate, $method, $path, $query, $requestBody, array $headerList)
    {
        $headerList      = AsrHeaders::canonicalize($headerList);
        $fullDate        = $headerList['x-amz-date'];
        $authHeaderParts = AsrAuthHeader::parse($headerList['authorization']);
        $credentialParts = explode('/', $authHeaderParts['credentials']);

        $validator = new AsrValidator();
        if (!$validator->validateCredentials($credentialParts)) {
            return false;
        }
        $accessKeyId = array_shift($credentialParts);
        $shortDate   = array_shift($credentialParts);
        if (!$validator->validateDates($serverDate, $fullDate, $shortDate)) {
            return false;
        }

        // look up secret key for access key id
        // credential scope check: {accessKeyId}/{shortDate}/{region:eu}/{service:ac-export|suite}/ems_request
        $secretKey = 'TODO-ADD-LOOKUP';

        $algorithm   = new AsrSigningAlgorithm(strtolower($authHeaderParts['algorithm']));
        $credentials = new AsrCredentials($fullDate, $accessKeyId, $credentialParts);
        $headers     = AsrHeaders::createFrom($headerList, $authHeaderParts['signed_headers']);
        $request     = new AsrRequest($algorithm, $credentials, $method, $path, $query, $requestBody, $headers);

        $signature = $request->signWith($algorithm, $credentials, $secretKey);
        return $authHeaderParts['signature'] == $signature;
    }
}

class AsrAuthHeader
{
    /**
     * @var AsrSigningAlgorithm
     */
    private $algorithm;

    /**
     * @var string
     */
    private $fullDate;

    /**
     * @var AsrCredentials
     */
    private $credentials;

    /**
     * @var AsrHeaders
     */
    private $headers;

    public static function create()
    {
        return new AsrAuthHeader();
    }

    public static function createDefault()
    {
        return self::create()->useAlgorithm(AsrUtil::SHA256)->useTimeStamp($_SERVER['REQUEST_TIME']);
    }

    public static function parse($authHeaderString)
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

    public function build($secretKey)
    {
        $signature = $this->request->signWith($secretKey);

        return $this->dateHeader() + array('Authorization' => $this->algorithm->toHeaderString() . ' ' .
            "Credential={$this->credentials->toHeaderString()}, " .
            "SignedHeaders={$this->headers->toHeaderString()}, ".
            "Signature=$signature");
    }

    /**
     * @param $algorithmName
     * @return AsrAuthHeader
     */
    public function useAlgorithm($algorithmName)
    {
        $this->algorithm = new AsrSigningAlgorithm($algorithmName);
        return $this;
    }

    /**
     * @param int $timeStamp
     * @return AsrAuthHeader
     */
    public function useTimeStamp($timeStamp)
    {
        $this->fullDate = AsrDateHelper::fromTimeStamp($timeStamp)->format(AsrDateHelper::AMAZON_DATE_FORMAT);
        return $this;
    }

    /**
     * @param string $accessKeyId
     * @param array $baseCredentials
     * @return AsrAuthHeader
     */
    public function useCredentials($accessKeyId, array $baseCredentials)
    {
        $this->credentials = new AsrCredentials($this->fullDate, $accessKeyId, $baseCredentials);
        return $this;
    }

    /**
     * @param string $host
     * @param array $headerList
     * @param array $headersToSign
     * @return AsrAuthHeader
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
     * @return AsrAuthHeader
     */
    public function useRequest($method, $path, $query, $requestBody)
    {
        $this->request = new AsrRequest($this->algorithm, $this->credentials, $method, $path, $query, $requestBody, $this->headers);
        return $this;
    }

    /**
     * @return array
     */
    public function dateHeader()
    {
        return array('X-Amz-Date' => $this->fullDate);
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
    private $fullDate;

    private $accessKeyId;

    /**
     * @var array
     */
    private $parts;

    public function __construct($fullDate, $accessKeyId, array $parts)
    {
        if (count($parts) != 3) {
            throw new AsrException('Credentials should consist of exactly 3 parts');
        }
        $this->fullDate = $fullDate;
        $this->accessKeyId = $accessKeyId;
        $this->parts = $parts;
    }

    public function toArray()
    {
        return array_merge(array($this->shortDate()), $this->parts);
    }

    public function toScopeString()
    {
        return implode('/', $this->toArray());
    }

    private function shortDate()
    {
        return substr($this->fullDate, 0, 8);
    }

    public function generateSigningKeyUsing(AsrSigningAlgorithm $algorithm, $secretKey)
    {
        $key = $secretKey;
        foreach ($this->toArray() as $data) {
            $key = $algorithm->hmac($data, $key, true);
        }
        return $key;
    }

    public function generateStringToSignUsing(AsrSigningAlgorithm $algorithm, $canonicalHash)
    {
        return implode("\n", array($algorithm->toHeaderString(), $this->fullDate, $this->toScopeString(), $canonicalHash));
    }

    public function toHeaderString()
    {
        return $this->accessKeyId . '/' . $this->toScopeString();
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
    private $headers;

    public function __construct(AsrSigningAlgorithm $algorithm, AsrCredentials $credentials, $method, $path, $query, $requestBody, AsrHeaders $headers)
    {
        $this->algorithm = $algorithm;
        $this->credentials = $credentials;
        $this->method = $method;
        $this->path = $path;
        $this->query = $query;
        $this->requestBody = $requestBody;
        $this->headers = $headers;
    }

    /**
     * Visibility is public only for testing
     * @param AsrSigningAlgorithm $algorithm
     * @return string
     */
    public function canonicalizeUsing(AsrSigningAlgorithm $algorithm)
    {
        $lines = array();
        $lines[] = strtoupper($this->method);
        $lines[] = $this->path;
        $lines[] = $this->query;
        foreach ($this->headers->collapse() as $headerLine) {
            $lines[] = $headerLine;
        }
        $lines[] = '';
        $lines[] = $this->headers->toHeaderString();
        $lines[] = $algorithm->hash($this->requestBody);

        return $algorithm->hash(implode("\n", $lines));
    }

    /**
     * @param string $secretKey
     * @return mixed
     */
    public function signWith($secretKey)
    {
        $canonicalHash = $this->canonicalizeUsing($this->algorithm);
        $stringToSign = $this->credentials->generateStringToSignUsing($this->algorithm, $canonicalHash);
        $signingKey = $this->credentials->generateSigningKeyUsing($this->algorithm, $secretKey);
        $signature = $this->algorithm->hmac($stringToSign, $signingKey, false);
        return $signature;
    }
}

class AsrValidator
{
    const ACCEPTABLE_TIME_INTERVAL_IN_SECONDS = 600;

    public function validateCredentials(array $credentialParts)
    {
        return 5 === count($credentialParts);
    }

    public function validateDates($serverDateString, $fullDateString, $shortDateString)
    {
        return substr($fullDateString, 0, 8) == $shortDateString
            && abs(strtotime($serverDateString) - strtotime($fullDateString)) < self::ACCEPTABLE_TIME_INTERVAL_IN_SECONDS;
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
