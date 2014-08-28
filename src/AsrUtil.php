<?php

class AsrUtil
{
    public static function generate($method, $url, $payload, array $headers, array $signedHeaders)
    {
        $urlParts = parse_url($url);

        $host = $urlParts['host'];
        $path = $urlParts['path'];
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';

        $requestLines = array_merge(
            array(strtoupper($method), $path, $query),
            self::convertHeaders($headers),
            array('', self::convertSignedHeaders($signedHeaders), hash('sha256', $payload))
        );

        return hash('sha256', implode("\n", $requestLines));
    }

    public static function createStringToSign($algo, $date, $credentialScope, $canonicalRequestHash)
    {
        return implode("\n", array($algo, $date, $credentialScope, $canonicalRequestHash));
    }

    public static function calculateSigningKey($date, $region, $service, $secretKey)
    {
        $secret = 'AWS4' . $secretKey;
        $hashedDate    = self::hmacSha($date, $secret);
        $hashedRegion  = self::hmacSha($region, $hashedDate);
        $hashedService = self::hmacSha($service, $hashedRegion);
        $signing       = self::hmacSha('aws4_request', $hashedService);
        return $signing;
    }

    private static function convertHeaders($headers)
    {
        $result = array();
        foreach ($headers as $key => $value) {
            $result []= strtolower($key) . ':' . self::trimHeaderValue($value);
        }
        return $result;
    }

    /**
     * @param $value
     * @return string
     */
    private static function trimHeaderValue($value)
    {
        return trim($value);
    }

    /**
     * @param array $signedHeaders
     * @return string
     */
    private static function convertSignedHeaders(array $signedHeaders)
    {
        return implode(';', array_map('strtolower', $signedHeaders));
    }

    /**
     * @param $data
     * @param $key
     * @param $raw
     * @return string
     */
    private static function hmacSha($data, $key, $raw = true)
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
