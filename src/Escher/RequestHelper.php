<?php

namespace Escher;


class RequestHelper
{
    private $serverVars;
    private $requestBody;
    private $authHeaderKey;
    private $dateHeaderKey;

    public function __construct(array $serverVars, $requestBody, $authHeaderKey, $dateHeaderKey)
    {
        $this->serverVars = $serverVars;
        $this->requestBody = $requestBody;
        $this->authHeaderKey = $authHeaderKey;
        $this->dateHeaderKey = $dateHeaderKey;
    }

    public function getRequestMethod()
    {
        return $this->serverVars['REQUEST_METHOD'];
    }

    public function getRequestBody()
    {
        return $this->requestBody;
    }

    public function getAuthElements($vendorKey, $algoPrefix)
    {
        $headerList = Utils::keysToLower($this->getHeaderList());
        $queryParams = $this->getQueryParams();
        if (isset($headerList[strtolower($this->authHeaderKey)])) {
            return AuthElements::parseFromHeaders($headerList, $this->authHeaderKey, $this->dateHeaderKey, $algoPrefix);
        }
        if($this->getRequestMethod() === 'GET' && isset($queryParams[$this->paramKey($vendorKey, 'Signature')])) {
            return AuthElements::parseFromQuery($headerList, $queryParams, $vendorKey, $algoPrefix);
        }
        throw new Exception('The authorization header is missing', Exception::CODE_MISSING_AUTH);
    }

    public function getTimeStamp()
    {
        return $this->serverVars['REQUEST_TIME'];
    }

    public function getHeaderList()
    {
        $headerList = $this->process($this->serverVars);
        $headerList['content-type'] = $this->getContentType();

        if (isset($headerList['host'])) {
            if (strpos($headerList['host'], ':') === false) {
                $host = $headerList['host'];
                $port = null;
            } else {
                list($host, $port) = explode(':', $headerList['host'], 2);
            }
            $headerList['host'] = $this->normalizeHost($host, $port);
        }

        return $headerList;
    }

    public function getCurrentUrl()
    {
        $scheme = (array_key_exists('HTTPS', $this->serverVars) && $this->serverVars['HTTPS'] == 'on') ? 'https' : 'http';
        $host = $this->getServerHost();
        return "$scheme://$host" . $this->serverVars['REQUEST_URI'];
    }

    private function process(array $serverVars)
    {
        $headerList = [];
        foreach ($serverVars as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerList[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            }
        }
        return $headerList;
    }

    private function getContentType()
    {
        return isset($this->serverVars['CONTENT_TYPE']) ? $this->serverVars['CONTENT_TYPE'] : '';
    }

    public function getServerHost()
    {
        return $this->normalizeHost($this->serverVars['SERVER_NAME'], $this->serverVars['SERVER_PORT']);
    }

    /**
     * @param $vendorKey
     * @param $paramId
     * @return string
     */
    private function paramKey($vendorKey, $paramId)
    {
        return 'X-' . $vendorKey . '-' . $paramId;
    }

    public function getQueryParams()
    {
        list(, $queryString) = array_pad(explode('?', $this->serverVars['REQUEST_URI'], 2), 2, '');
        parse_str($queryString, $result);
        return $result;
    }

    private function normalizeHost($host, $port)
    {
        if (is_null($port) || $this->isDefaultPort($port)) {
            return $host;
        }

        return $host . ':' . $port;
    }

    private function isDefaultPort($port)
    {
        $defaultPort = isset($this->serverVars['HTTPS']) && $this->serverVars['HTTPS'] === 'on' ? '443' : '80';
        return $port == $defaultPort;
    }
}
