<?php

namespace Escher;


class AuthElements
{
    private $elementParts;
    private $accessKeyId;
    private $shortDate;
    private $credentialScope;
    private $dateTime;
    private $host;
    private $isFromHeaders;

    public function __construct(array $elementParts, $accessKeyId, $shortDate, $credentialScope, \DateTime $dateTime, $host, $isFromHeaders)
    {
        $this->elementParts = $elementParts;
        $this->accessKeyId = $accessKeyId;
        $this->shortDate = $shortDate;
        $this->credentialScope = $credentialScope;
        $this->dateTime = $dateTime;
        $this->host = $host;
        $this->isFromHeaders = $isFromHeaders;
    }

    /**
     * @param array $headerList
     * @param $authHeaderKey
     * @param $dateHeaderKey
     * @param $algoPrefix
     * @return AuthElements
     * @throws Exception
     */
    public static function parseFromHeaders(array $headerList, $authHeaderKey, $dateHeaderKey, $algoPrefix)
    {
        $headerList = Utils::keysToLower($headerList);
        $elementParts = self::parseAuthHeader($headerList[strtolower($authHeaderKey)], $algoPrefix);
        list($accessKeyId, $shortDate, $credentialScope) = explode('/', $elementParts['Credentials'], 3);
        $host = self::checkHost($headerList);

        if (!isset($headerList[strtolower($dateHeaderKey)])) {
            throw new Exception('The '.strtolower($dateHeaderKey).' header is missing');
        }

        if (strtolower($dateHeaderKey) !== 'date') {
            $dateTime = Utils::parseLongDate($headerList[strtolower($dateHeaderKey)]);
        } else {
            try {
                $dateTime = new \DateTime($headerList[strtolower($dateHeaderKey)], new \DateTimeZone('GMT'));
            } catch (Exception $ex) {
                throw new Exception('Date header is invalid, the expected format is Wed, 04 Nov 2015 09:20:22 GMT');
            }
        }
        return new AuthElements($elementParts, $accessKeyId, $shortDate, $credentialScope, $dateTime, $host, true);
    }

    /**
     * @param $headerContent
     * @param $algoPrefix
     * @return array
     * @throws Exception
     */
    public static function parseAuthHeader($headerContent, $algoPrefix)
    {
        $pattern = '/^' . $algoPrefix . '-HMAC-([A-Z0-9\,]+)(.*)' .
                                     'Credential=([A-Za-z0-9\/\-_]+),(.*)' .
                                     'SignedHeaders=([A-Za-z\-;]+),(.*)' .
                                     'Signature=([0-9a-f]+)$/';

        if (!preg_match($pattern, $headerContent, $matches)) {
            throw new Exception('Auth header format is invalid');
        }
        return array(
            'Algorithm'     => $matches[1],
            'Credentials'   => $matches[3],
            'SignedHeaders' => $matches[5],
            'Signature'     => $matches[7],
        );
    }

    public static function parseFromQuery($headerList, $queryParams, $vendorKey, $algoPrefix)
    {
        $elementParts = array();
        $paramKey = self::checkParam($queryParams, $vendorKey, 'Algorithm');

        $pattern = '/^' . $algoPrefix . '-HMAC-([A-Z0-9\,]+)$/';
        if (!preg_match($pattern, $queryParams[$paramKey], $matches))
        {
            throw new Exception('invalid ' . $paramKey . ' query key format');
        }
        $elementParts['Algorithm'] = $matches[1];

        foreach (self::basicQueryParamKeys() as $paramId) {
            $paramKey = self::checkParam($queryParams, $vendorKey, $paramId);
            $elementParts[$paramId] = $queryParams[$paramKey];
        }
        list($accessKeyId, $shortDate, $credentialScope) = explode('/', $elementParts['Credentials'], 3);
        $dateTime = Utils::parseLongDate($elementParts['Date']);
        return new AuthElements($elementParts, $accessKeyId, $shortDate, $credentialScope, $dateTime, self::checkHost($headerList), false);
    }

    private static function basicQueryParamKeys()
    {
        return array(
            'Credentials',
            'Date',
            'Expires',
            'SignedHeaders',
            'Signature'
        );
    }

    /**
     * @param $queryParams
     * @param $vendorKey
     * @param $paramId
     * @return string
     * @throws Exception
     */
    private static function checkParam($queryParams, $vendorKey, $paramId)
    {
        $paramKey = 'X-' . $vendorKey . '-' . $paramId;
        if (!isset($queryParams[$paramKey])) {
            throw new Exception('Query key: ' . $paramKey . ' is missing');
        }
        return $paramKey;
    }

    private static function checkHost($headerList)
    {
        if (!isset($headerList['host'])) {
            throw new Exception('The host header is missing');
        }
        return $headerList['host'];
    }

    public function validateDates(RequestHelper $helper, $clockSkew)
    {
        $shortDate = $this->dateTime->format('Ymd');
        if ($shortDate !== $this->getShortDate()) {
            throw new Exception('Date in the authorization header is invalid. It must be the same as the date header');
        }

        if (!$this->isInAcceptableInterval($helper->getTimeStamp(), Utils::getTimeStampOfDateTime($this->dateTime), $clockSkew)) {
            throw new Exception('The request date is not within the accepted time range');
        }
    }

    public function validateCredentials($credentialScope)
    {
        if (!$this->checkCredentials($credentialScope)) {
            throw new Exception('Credential scope is invalid');
        }
    }

    private function checkCredentials($credentialScope)
    {
        return $this->credentialScope === $credentialScope;
    }

    public function validateSignature(RequestHelper $helper, Escher $escher, $keyDB, $vendorKey)
    {
        $secret = $this->lookupSecretKey($this->accessKeyId, $keyDB);

        $headers = $helper->getHeaderList();
        $calculated = $escher->getSignature(
            $secret,
            $this->dateTime,
            $helper->getRequestMethod(),
            $this->stripAuthParams($helper, $vendorKey),
            $this->isFromHeaders ? $helper->getRequestBody() : Escher::UNSIGNED_PAYLOAD,
            $headers,
            $this->getSignedHeaders()
        );

        $provided = $this->getSignature();
        if ($calculated !== $provided) {
            throw new Exception("The signatures do not match");
        }
    }

    private function lookupSecretKey($accessKeyId, $keyDB)
    {
        if (!isset($keyDB[$accessKeyId])) {
            throw new Exception('Invalid Escher key');
        }
        return $keyDB[$accessKeyId];
    }

    public function validateHashAlgo()
    {
        if(!in_array(strtoupper($this->getAlgorithm()), array('SHA256','SHA512')))
        {
            throw new Exception('Hash algorithm is invalid. Only SHA256 and SHA512 are allowed');
        }
    }

    /**
     * @param string $dateHeaderKey
     * @throws Exception
     */
    public function validateMandatorySignedHeaders($dateHeaderKey)
    {
        $signedHeaders = $this->getSignedHeaders();
        if (!in_array('host', $signedHeaders)) {
            throw new Exception('The host header is not signed');
        }
        if ($this->isFromHeaders && !in_array(strtolower($dateHeaderKey), $signedHeaders)) {
            throw new Exception('The ' . strtolower($dateHeaderKey) . ' header is not signed');
        }
    }

    public function getAccessKeyId()
    {
        return $this->accessKeyId;
    }

    public function getShortDate()
    {
        return $this->shortDate;
    }

    public function getSignedHeaders()
    {
        return explode(';', $this->elementParts['SignedHeaders']);
    }

    public function getSignature()
    {
        return $this->elementParts['Signature'];
    }

    public function getAlgorithm()
    {
        return $this->elementParts['Algorithm'];
    }

    public function getHost()
    {
        return $this->host;
    }

    /**
     * @param RequestHelper $helper
     * @param $vendorKey
     * @return string
     */
    private function stripAuthParams(RequestHelper $helper, $vendorKey)
    {
        $url = $helper->getCurrentUrl();
        $signaturePattern = "/(?P<prefix>[?&])X-${vendorKey}-Signature=[a-fA-F0-9]{64}(?P<suffix>&?)/";

        return preg_replace_callback($signaturePattern, array($this, 'handleStripAuthParamMatches'), $url);
    }

    private function getExpires()
    {
        return $this->isFromHeaders ? 0 : $this->elementParts['Expires'];
    }

    private function isInAcceptableInterval($currentTimeStamp, $requestTimeStamp, $clockSkew)
    {
        return ($requestTimeStamp - $clockSkew <= $currentTimeStamp)
            && ($currentTimeStamp <= $requestTimeStamp + $this->getExpires() + $clockSkew);
    }

    public function getCredentialScope()
    {
        return $this->credentialScope;
    }

    public function getDateTime()
    {
        return $this->dateTime;
    }

    private function handleStripAuthParamMatches($matches) {
        return (!empty($matches['suffix']) || $matches['prefix'] === '?')
            ? $matches['prefix']
            : $matches['suffix'];
    }
}
