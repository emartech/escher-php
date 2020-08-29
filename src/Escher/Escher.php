<?php

namespace Escher;

use DateTime;
use DateTimeZone;

class Escher
{
    const DEFAULT_HASH_ALGORITHM = 'SHA256';
    const DEFAULT_ALGO_PREFIX = 'ESR';
    const DEFAULT_VENDOR_KEY = 'Escher';
    const DEFAULT_AUTH_HEADER_KEY = 'X-Escher-Auth';
    const DEFAULT_DATE_HEADER_KEY = 'X-Escher-Date';
    const DEFAULT_CLOCK_SKEW = 300;
    const DEFAULT_EXPIRES = 86400;
    const ISO8601 = 'Ymd\THis\Z';
    const LONG_DATE = self::ISO8601;
    const SHORT_DATE = 'Ymd';
    const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

    private $credentialScope;
    private $clockSkew = self::DEFAULT_CLOCK_SKEW;
    private $hashAlgo = self::DEFAULT_HASH_ALGORITHM;
    private $algoPrefix = self::DEFAULT_ALGO_PREFIX;
    private $vendorKey = self::DEFAULT_VENDOR_KEY;
    private $authHeaderKey = self::DEFAULT_AUTH_HEADER_KEY;
    private $dateHeaderKey = self::DEFAULT_DATE_HEADER_KEY;

    public function __construct($credentialScope)
    {
        $this->credentialScope = $credentialScope;
    }

    public static function create($credentialScope)
    {
        return new Escher($credentialScope);
    }

    /**
     * @return DateTime
     */
    private static function now()
    {
        return new DateTime('now', new DateTimeZone('GMT'));
    }

    /**
     * @param $keyDB
     * @param array|null $serverVars
     * @param null $requestBody
     * @return mixed
     * @throws Exception
     */
    public function authenticate($keyDB, array $serverVars = null, $requestBody = null)
    {
        $serverVars = null === $serverVars ? $_SERVER : $serverVars;
        $requestBody = null === $requestBody ? $this->fetchRequestBodyFor($serverVars['REQUEST_METHOD']) : $requestBody;

        $algoPrefix = $this->algoPrefix;
        $vendorKey = $this->vendorKey;
        $helper = new RequestHelper($serverVars, $requestBody, $this->authHeaderKey, $this->dateHeaderKey);
        $authElements = $helper->getAuthElements($this->vendorKey, $algoPrefix);

        $authElements->validateMandatorySignedHeaders($this->dateHeaderKey);
        $authElements->validateHashAlgo();
        $authElements->validateDates($helper, $this->clockSkew);
        $authElements->validateCredentials($helper, $this->credentialScope);
        $authElements->validateSignature($helper, $this, $keyDB, $vendorKey);
        return $authElements->getAccessKeyId();
    }

    public function presignUrl($accessKeyId, $secretKey, $url, $expires = Escher::DEFAULT_EXPIRES, DateTime $date = null)
    {
        $date = $date ? $date : self::now();
        $url = $this->appendSigningParams($accessKeyId, $url, $date, $expires);

        list($host, $path, $query) = $this->parseUrl($url);

        list($signature) = $this->calculateSignature(
            $secretKey,
            $date,
            'GET',
            $path,
            $query,
            self::UNSIGNED_PAYLOAD,
            array('host' => $host),
            (array('host'))
        );
        $url = $this->addGetParameter($url, $this->generateParamName('Signature'), $signature);

        return $url;
    }

    public function signRequest($accessKeyId, $secretKey, $method, $url, $requestBody, $headerList = array(), $headersToSign = array(), DateTime $date = null)
    {
        $date = $date ? $date : self::now();
        list($host, $path, $query) = $this->parseUrl($url);
        list($headerList, $headersToSign) = $this->addMandatoryHeaders(
            $headerList, $headersToSign, $this->dateHeaderKey, $date, $host
        );

        return $headerList + $this->generateAuthHeader(
            $secretKey,
            $accessKeyId,
            $this->authHeaderKey,
            $date,
            $method,
            $path,
            $query,
            $requestBody,
            $headerList,
            $headersToSign
        );
    }

    private function appendSigningParams($accessKeyId, $url, $date, $expires)
    {
        $signingParams = array(
            'Algorithm'     => $this->algoPrefix. '-HMAC-' . $this->hashAlgo,
            'Credentials'   => $accessKeyId . '/' . $this->fullCredentialScope($date),
            'Date'          => $this->toLongDate($date),
            'Expires'       => $expires,
            'SignedHeaders' => 'host',
        );
        foreach ($signingParams as $param => $value)
        {
            $url = $this->addGetParameter($url, $this->generateParamName($param), $value);
        }
        return $url;
    }

    private function generateParamName($param)
    {
        return 'X-' . $this->vendorKey . '-' . $param;
    }

    public function getSignature($secretKey, DateTime $date, $method, $url, $requestBody, $headerList, $signedHeaders)
    {
        list(, $path, $query) = $this->parseUrl($url);
        return $this->calculateSignature($secretKey, $date, $method, $path, $query, $requestBody, $headerList, $signedHeaders);
    }

    private function parseUrl($url)
    {
        $urlParts = parse_url($url);
        $defaultPort = $urlParts['scheme'] === 'http' ? 80 : 443;
        $host = $urlParts['host'] . (isset($urlParts['port']) && $urlParts['port'] != $defaultPort ? ':' . $urlParts['port'] : '');
        $path = isset($urlParts['path']) ? $urlParts['path'] : null;
        $query = isset($urlParts['query']) ? $urlParts['query'] : '';
        return array($host, $path, $query);
    }

    private function toLongDate(DateTime $date)
    {
        return $date->format(self::LONG_DATE);
    }

    private function addGetParameter($url, $key, $value)
    {
        $glue = '?';
        if (strpos($url, '?') !== false) {
            $glue = '&';
        }

        $fragmentPosition = strpos($url, '#');
        if ($fragmentPosition === false) {
            return $url . $glue . $key . '=' . urlencode($value);
        }
        else {
            return substr_replace($url, ($glue . $key . '=' . urlencode($value)), $fragmentPosition, 0);
        }
    }

    /**
     * @param $date
     * @return string
     */
    private function fullCredentialScope(DateTime $date)
    {
        return $date->format(self::SHORT_DATE) . '/' . $this->credentialScope;
    }

    private function generateAuthHeader($secretKey, $accessKeyId, $authHeaderKey, $date, $method, $path, $query, $requestBody, array $headerList, array $headersToSign)
    {
        list($signature) = $this->calculateSignature($secretKey, $date, $method, $path, $query, $requestBody, $headerList, $headersToSign);
        $authHeaderValue = Signer::createAuthHeader(
            $signature,
            $this->fullCredentialScope($date),
            implode(';', $headersToSign),
            $this->hashAlgo,
            $this->algoPrefix,
            $accessKeyId
        );
        return array(strtolower($authHeaderKey) => $authHeaderValue);
    }

    private function calculateSignature($secretKey, $date, $method, $path, $query, $requestBody, array $headerList, array $headersToSign)
    {
        $hashAlgo = $this->hashAlgo;
        $algoPrefix = $this->algoPrefix;
        $requestUri = $path . ($query ? '?' . $query : '');
        // canonicalization works with raw headers
        $rawHeaderLines = array();
        foreach ($headerList as $headerKey => $headerValue) {
            $rawHeaderLines []= $headerKey . ':' . $headerValue;
        }
        $canonicalizedRequest = RequestCanonicalizer::canonicalize(
            $method,
            $requestUri,
            $requestBody,
            implode("\n", $rawHeaderLines),
            $headersToSign,
            $hashAlgo
        );

        $stringToSign = Signer::createStringToSign(
            $this->credentialScope,
            $canonicalizedRequest,
            $date,
            $hashAlgo,
            $algoPrefix
        );

        $signerKey = Signer::calculateSigningKey(
            $secretKey,
            $this->fullCredentialScope($date),
            $hashAlgo,
            $algoPrefix
        );

        $signature = Signer::createSignature(
            $stringToSign,
            $signerKey,
            $hashAlgo
        );

        return array(
            $signature, $canonicalizedRequest
        );
    }

    /**
     * @param $headerList
     * @param $headersToSign
     * @param $dateHeaderKey
     * @param $date
     * @param $host
     * @return array
     */
    private function addMandatoryHeaders($headerList, $headersToSign, $dateHeaderKey, $date, $host)
    {
        $mandatoryHeaders = array(strtolower($dateHeaderKey) => $this->toLongDate($date), 'host' => $host);
        $headerList = Utils::keysToLower($headerList) + $mandatoryHeaders;
        $headersToSign = array_unique(array_merge(array_map('strtolower', $headersToSign), array_keys($mandatoryHeaders)));
        sort($headersToSign);
        return array($headerList, $headersToSign);
    }

    /**
     * php://input may contain data even though the request body is empty, e.g. in GET requests
     *
     * @param string
     * @return string
     */
    private function fetchRequestBodyFor($method)
    {
        return in_array($method, array('PUT', 'POST')) ? file_get_contents('php://input') : '';
    }

    /**
     * @param $clockSkew
     * @return Escher
     */
    public function setClockSkew($clockSkew)
    {
        $this->clockSkew = $clockSkew;
        return $this;
    }

    /**
     * @param $hashAlgo
     * @return Escher
     */
    public function setHashAlgo($hashAlgo)
    {
        $this->hashAlgo = strtoupper($hashAlgo);
        return $this;
    }

    /**
     * @param $algoPrefix
     * @return Escher
     */
    public function setAlgoPrefix($algoPrefix)
    {
        $this->algoPrefix = strtoupper($algoPrefix);
        return $this;
    }

    /**
     * @param $vendorKey
     * @return Escher
     */
    public function setVendorKey($vendorKey)
    {
        $this->vendorKey = $vendorKey;
        return $this;
    }

    /**
     * @param $authHeaderKey
     * @return Escher
     */
    public function setAuthHeaderKey($authHeaderKey)
    {
        $this->authHeaderKey = $authHeaderKey;
        return $this;
    }

    /**
     * @param $dateHeaderKey
     * @return Escher
     */
    public function setDateHeaderKey($dateHeaderKey)
    {
        $this->dateHeaderKey = $dateHeaderKey;
        return $this;
    }
}
