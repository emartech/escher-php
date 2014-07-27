<?php

class AsrUtil
{
    const SHA256 = 'sha256';

    public function signRequest($algorithmName, $secretKey, $accessKeyId, array $baseCredentials, $fullDate, $method, $url, $requestBody, array $headerList)
    {
        $algorithm   = new AsrSigningAlgorithm($algorithmName);
        $credentials = new AsrCredentials($fullDate, $accessKeyId, $baseCredentials);
        $headers     = AsrHeaders::createFrom($headerList);
        $request     = new AsrRequest($method, $url, $requestBody, $headers);

        $signature = $this->calculateSignature($algorithm, $secretKey, $credentials, $request);

        $authHeader = new AsrAuthHeader($algorithm, $credentials, $headers, $signature);
        return array('X-Amz-Date' => $fullDate, 'Authorization' => $authHeader->toHeaderString());
    }

    public function validateSignature($serverDate, $method, $url, $requestBody, array $headerList)
    {
        $validator = new AsrValidator();
        $headers = AsrHeaders::createFrom($headerList);
        $authHeaderParts = AsrAuthHeader::parse($headers->get('authorization'));
        $credentialParts = explode('/', $authHeaderParts['credentials']);
        if (!$validator->validateCredentials($credentialParts)) {
            return false;
        }
        $accessKeyId = array_shift($credentialParts);
        $shortDate   = array_shift($credentialParts);
        $fullDate    = $headers->get('x-amz-date');
        if (!$validator->validateDates($serverDate, $fullDate, $shortDate)) {
            return false;
        }

        // look up secret key for access key id
        // credential scope check: {accessKeyId}/{shortDate}/{region:eu}/{service:ac-export|suite}/ems_request
        $secretKey = 'TODO-ADD-LOOKUP';

        $algorithm   = new AsrSigningAlgorithm(strtolower($authHeaderParts['algorithm']));
        $credentials = new AsrCredentials($fullDate, $accessKeyId, $credentialParts);
        $request     = new AsrRequest($method, $url, $requestBody, $headers);

        $signature = $this->calculateSignature($algorithm, $secretKey, $credentials, $request);
        return $authHeaderParts['signature'] == $signature;
    }

    /**
     * @param $algorithm
     * @param $secretKey
     * @param $credentials
     * @param $request
     * @return mixed
     */
    public function calculateSignature($algorithm, $secretKey, $credentials, $request)
    {
        $canonicalHash = $request->canonicalizeUsing($algorithm);
        $stringToSign = $credentials->generateStringToSignUsing($algorithm, $canonicalHash);
        $signingKey = $credentials->generateSigningKeyUsing($algorithm, $secretKey);
        $signature = $algorithm->hmac($stringToSign, $signingKey, false);
        return $signature;
    }
}

class AsrAuthHeader
{
    /**
     * @var AsrSigningAlgorithm
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
     * @var string
     */
    private $signature;

    public function __construct($algorithm, $credentials, $headers, $signature)
    {
        $this->algorithm = $algorithm;
        $this->credentials = $credentials;
        $this->headers = $headers;
        $this->signature = $signature;
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

    public function toHeaderString()
    {
        return $this->algorithm->toHeaderString() . ' ' .
                "Credential={$this->credentials->toHeaderString()}, " .
                "SignedHeaders={$this->headers->toHeaderString()}, ".
                "Signature=$this->signature";
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

    public function __construct(array $headerList)
    {
        $this->headerList = $headerList;
    }

    public static function createFrom($headerList)
    {
        ksort($headerList);
        return new AsrHeaders(array_combine(
            array_map('strtolower', array_keys($headerList)),
            array_map('self::trimHeaderValue', array_values($headerList))
        ));
    }

    public static function trimHeaderValue($value)
    {
        return trim($value);
    }

    public function get($headerKey)
    {
        return isset($this->headerList[$headerKey]) ? $this->headerList[$headerKey] : '';
    }

    public function toHeaderString()
    {
        return implode(';', array_keys($this->headerList));
    }

    public function canonicalize()
    {
        return array_map(
            array($this, 'collapseLine'),
            array_keys($this->headerList),
            array_values($this->headerList)
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
    private $url;
    private $headers;

    public function __construct($method, $url, $payload, AsrHeaders $headers)
    {
        $this->method = $method;
        $this->url = $url;
        $this->payload = $payload;
        $this->headers = $headers;
    }

    public function canonicalizeUsing(AsrSigningAlgorithm $algorithm)
    {
        $urlParts = parse_url($this->url);

        $lines = array();
        $lines[] = strtoupper($this->method);
        $lines[] = $urlParts['path'];
        $lines[] = isset($urlParts['query']) ? $urlParts['query'] : '';
        foreach ($this->headers->canonicalize() as $canonicalizedHeaderLine) {
            $lines[] = $canonicalizedHeaderLine;
        }
        $lines[] = '';
        $lines[] = $this->headers->toHeaderString();
        $lines[] = $algorithm->hash($this->payload);

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

    public function validateDates($serverDateString, $fullDateString, $shortDateString)
    {
        return substr($fullDateString, 0, 8) == $shortDateString
            && abs(strtotime($serverDateString) - strtotime($fullDateString)) < self::ACCEPTABLE_TIME_INTERVAL_IN_SECONDS;
    }
}

class AsrException extends Exception
{
}
