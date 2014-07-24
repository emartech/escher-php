<?php

class AsrUtil
{
    public function generate($method, $url, $payload, array $headers, array $signedHeaders)
    {
        $urlParts = parse_url($url);

        $host = $urlParts['host'];
        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';

        $requestLines = array_merge(
            array(strtoupper($method), $path, $query),
            $this->convertHeaders($headers),
            array('', $this->convertSignedHeaders($signedHeaders), hash('sha256', $payload))
        );

        return hash('sha256', implode("\n", $requestLines));
    }

    public function createStringToSign($algorithm, $date, $credentialScope, $canonicalRequestHash)
    {
        return implode("\n", array($algorithm, $date, $credentialScope, $canonicalRequestHash));
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
        return hash_hmac('sha256', $data, $key, $raw);
    }

    public function signRequest($stringToSign, $date, $region, $service, $secretKey)
    {
        return $this->hmacSha(
            $stringToSign,
            $this->calculateSigningKey($date, $region, $service, $secretKey),
            false
        );
    }
}
