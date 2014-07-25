<?php

class AsrUtil
{
    /**
     * @var SigningAlgorithm
     */
    private $algorithm;

    /**
     * @param SigningAlgorithm $algorithm
     */
    public function __construct(SigningAlgorithm $algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public function signRequest($secretKey, $accessKeyId, array $baseCredentials, $fullDate, $method, $url, $payload, array $headers)
    {
        $credentials   = new AsrCredentials($fullDate, $baseCredentials);
        $headersObject = new AsrHeaders($headers);
        $request       = new AsrRequest($method, $url, $payload, $headersObject);

        $canonicalHash   = $request->canonicalizeUsing($this->algorithm);

        $stringToSign    = $this->generateStringToSign($fullDate, $credentials, $canonicalHash);
        $signingKey      = $credentials->generateSigningKeyUsing($this->algorithm, $secretKey);
        $signature       = $this->algorithm->hmac($stringToSign, $signingKey, false);
        $result          = array(
            'Authorization' => $this->buildAuthorizationHeader($accessKeyId, $headers, $credentials->toScopeString(), $signature),
            'X-Amz-Date'    => $fullDate,
        );
        return $result;
    }

    public function validateSignature(array $request, array $headers)
    {
        // parse authorization header
        // credential scope check: {accessKeyId}/{shortDate}/{region:eu}/{service:ac-export|suite}/ems_request
        // credential scope date's day should equal to x-amz-date
        // x-amz-date should be within X minutes of server's time
        // signature check:
    }

    public function sign($stringToSign, AsrCredentials $credentials, $secretKey)
    {
        $signingKey = $credentials->generateSigningKeyUsing($this->algorithm, $secretKey);
        return $this->algorithm->hmac($stringToSign, $signingKey, false);
    }

    public function generateStringToSign($fullDate, AsrCredentials $credentials, $canonicalHash)
    {
        return implode("\n", array($this->algorithm->getName(), $fullDate, $credentials->toScopeString(), $canonicalHash));
    }

    public function generateCanonicalHash($method, $url, $payload, array $headers)
    {
        $headers = new AsrHeaders($headers);
        $request = new AsrRequest($method, $url, $payload, $headers);
        return $request->canonicalizeUsing($this->algorithm);
    }

    /**
     * @param $accessKeyId
     * @param array $headers
     * @param $credentialScope
     * @param $signature
     * @return string
     */
    private function buildAuthorizationHeader($accessKeyId, array $headers, $credentialScope, $signature)
    {
        $headers = new AsrHeaders($headers);
        return "{$this->algorithm->getName()} Credential=$accessKeyId/$credentialScope, SignedHeaders={$headers->toSignedHeadersString()}, Signature=$signature";
    }
}

class SigningAlgorithm
{
    const SHA_256 = 'sha256';

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;
    }

    public function getName()
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

    /**
     * @var array
     */
    private $parts;

    public function __construct($fullDate, array $parts)
    {
        if (count($parts) != 3) {
            throw new InvalidArgumentException('Credentials should consist of exactly 3 parts');
        }
        $this->fullDate = $fullDate;
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

    public function generateSigningKeyUsing(SigningAlgorithm $algorithm, $secretKey)
    {
        $key = $secretKey;
        foreach ($this->toArray() as $data) {
            $key = $algorithm->hmac($data, $key, true);
        }
        return $key;
    }
}

class AsrHeaders
{
    public function __construct($headers)
    {
        $this->headers = $headers;
    }

    public function toSignedHeadersString()
    {
        return implode(';', array_map('strtolower', array_keys($this->headers)));
    }

    public function canonicalize()
    {
        $result = array();
        foreach ($this->headers as $key => $value) {
            $result []= strtolower($key) . ':' . $this->trimHeaderValue($value);
        }
        return $result;
    }

    /**
     * @param $value
     * @return string
     */
    private function trimHeaderValue($value)
    {
        return trim($value);
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

    public function canonicalizeUsing(SigningAlgorithm $algorithm)
    {
        $urlParts = parse_url($this->url);

        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';

        $requestLines = array_merge(
            array(strtoupper($this->method), $path, $query),
            $this->headers->canonicalize(),
            array('', $this->headers->toSignedHeadersString(), $algorithm->hash($this->payload))
        );
        return $algorithm->hash(implode("\n", $requestLines));
    }
}
