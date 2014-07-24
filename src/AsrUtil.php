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

    public function signRequest($secretKey, $accessKeyId, array $baseCredentials, $fullDate, $method, $url, $payload, array $headers, array $signedHeaders)
    {
        $shortDate       = substr($fullDate, 0, 8);
        $credentials     = array_merge(array($shortDate), $baseCredentials);
        $credentialScope = implode('/', $credentials);
        $canonicalHash   = $this->generateCanonicalHash($method, $url, $payload, $headers, $signedHeaders);
        $stringToSign    = $this->generateStringToSign($fullDate, $credentialScope, $canonicalHash);
        $signingKey      = $this->generateSigningKey($credentials, $secretKey);
        $signature       = $this->algorithm->hmac($stringToSign, $signingKey, false);
        $result          = array(
            'Authorization' => $this->buildAuthorizationHeader($accessKeyId, $signedHeaders, $credentialScope, $signature),
            'X-Amz-Date'    => $fullDate,
        );
        return $result;
    }

    public function sign($stringToSign, array $credentials, $secretKey)
    {
        $signingKey = $this->generateSigningKey($credentials, $secretKey);
        return $this->algorithm->hmac($stringToSign, $signingKey, false);
    }

    public function generateSigningKey(array $credentials, $secretKey)
    {
        $key = $secretKey;
        foreach ($credentials as $data) {
            $key = $this->algorithm->hmac($data, $key, true);
        }
        return $key;
    }

    public function generateStringToSign($date, $credentialScope, $canonicalHash)
    {
        return implode("\n", array($this->algorithm->getName(), $date, $credentialScope, $canonicalHash));
    }

    public function generateCanonicalHash($method, $url, $payload, array $headers, array $signedHeaders)
    {
        $urlParts = parse_url($url);

        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';

        $requestLines = array_merge(
            array(strtoupper($method), $path, $query),
            $this->convertHeaders($headers),
            array('', $this->convertSignedHeaders($signedHeaders), $this->algorithm->hash($payload))
        );

        return $this->algorithm->hash(implode("\n", $requestLines));
    }

    private function convertHeaders($headers)
    {
        $result = array();
        foreach ($headers as $key => $value) {
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

    /**
     * @param array $signedHeaders
     * @return string
     */
    private function convertSignedHeaders(array $signedHeaders)
    {
        return implode(';', array_map('strtolower', $signedHeaders));
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
