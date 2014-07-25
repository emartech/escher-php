<?php

class AsrUtil
{
    const SHA256 = 'sha256';

    public function signRequest($algorithmName, $secretKey, $accessKeyId, array $baseCredentials, $fullDate, $method, $url, $payload, array $headers)
    {
        $algorithm     = new SigningAlgorithm($algorithmName);
        $credentials   = new AsrCredentials($fullDate, $baseCredentials);
        $headersObject = new AsrHeaders($headers);
        $request       = new AsrRequest($method, $url, $payload, $headersObject);

        $canonicalHash   = $request->canonicalizeUsing($algorithm);

        $stringToSign    = $credentials->generateStringToSignUsing($algorithm, $canonicalHash);
        $signingKey      = $credentials->generateSigningKeyUsing($algorithm, $secretKey);
        $signature       = $algorithm->hmac($stringToSign, $signingKey, false);

        $result          = array(
            'Authorization' => "{$algorithm->getNameForHeader()} Credential=$accessKeyId/{$credentials->toScopeString()}, SignedHeaders={$headersObject->toSignedHeadersString()}, Signature=$signature",
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
}

class SigningAlgorithm
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
        $this->algorithm = $algorithm;
    }

    public function getNameForHeader()
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

    public function generateStringToSignUsing(SigningAlgorithm $algorithm, $canonicalHash)
    {
        return implode("\n", array($algorithm->getNameForHeader(), $this->fullDate, $this->toScopeString(), $canonicalHash));
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

        $lines = array();
        $lines[] = strtoupper($this->method);
        $lines[] = $urlParts['path'];
        $lines[] = isset($urlParts['query']) ? $urlParts['query'] : '';
        foreach ($this->headers->canonicalize() as $canonicalizedHeaderLine) {
            $lines[] = $canonicalizedHeaderLine;
        }
        $lines[] = '';
        $lines[] = $this->headers->toSignedHeadersString();
        $lines[] = $algorithm->hash($this->payload);

        return $algorithm->hash(implode("\n", $lines));
    }
}
