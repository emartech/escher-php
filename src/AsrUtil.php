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

    public function signRequest($stringToSign, $date, $region, $service, $secretKey)
    {
        $signingKey = $this->calculateSigningKey($date, $region, $service, $secretKey);
        return $this->algorithm->hmac($stringToSign, $signingKey, false);
    }

    public function calculateSigningKey($date, $region, $service, $secretKey)
    {
        $secret = 'AWS4' . $secretKey;
        $hashedDate    = $this->hmacSha($date, $secret);
        $hashedRegion  = $this->hmacSha($region, $hashedDate);
        $hashedService = $this->hmacSha($service, $hashedRegion);
        $signing       = $this->hmacSha('aws4_request', $hashedService);
        return $signing;
    }

    public function createStringToSign($date, $credentialScope, $canonicalHash)
    {
        return implode("\n", array($this->algorithm->getName(), $date, $credentialScope, $canonicalHash));
    }

    public function generateCanonicalHash($method, $url, $payload, array $headers, array $signedHeaders)
    {
        $urlParts = parse_url($url);

        $host = $urlParts['host'];
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

    /**
     * @param $data
     * @param $key
     * @param $raw
     * @return string
     */
    private function hmacSha($data, $key, $raw = true)
    {
        return $this->algorithm->hmac($data, $key, $raw);
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
