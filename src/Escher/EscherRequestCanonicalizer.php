<?php

namespace Escher;


class EscherRequestCanonicalizer
{
    public static function canonicalize($method, $requestUri, $payload, $rawHeaders, array $headersToSign, $hashAlgo)
    {
        list($path, $query) = array_pad(explode('?', $requestUri, 2), 2, '');
        $lines = array();
        $lines[] = strtoupper($method);
        $lines[] = self::normalizePath($path);
        $lines[] = self::urlEncodeQueryString($query);

        sort($headersToSign);
        $lines = array_merge($lines, self::canonicalizeHeaders($rawHeaders, $headersToSign));

        $lines[] = '';
        $lines[] = implode(";", $headersToSign);

        $lines[] = hash($hashAlgo, $payload);

        return implode("\n", $lines);
    }

    public static function urlEncodeQueryString($query)
    {
        if (empty($query)) return "";
        $pairs = explode("&", $query);
        $encodedParts = array();
        foreach ($pairs as $pair) {
            $keyValues = array_pad(explode("=", $pair), 2, '');
            if (strpos($keyValues[0], " ") !== false) {
                $keyValues[0] = substr($keyValues[0], 0, strpos($keyValues[0], " "));
                $keyValues[1] = "";
            }
            $keyValues[0] = urldecode($keyValues[0]);
            $keyValues[1] = urldecode($keyValues[1]);
            $encodedParts[] = implode("=", array(
                self::rawUrlEncode(str_replace('+', ' ', $keyValues[0])),
                self::rawUrlEncode(str_replace('+', ' ', $keyValues[1])),
            ));
        }
        sort($encodedParts);
        return implode("&", $encodedParts);
    }

    private static function normalizePath($path)
    {
        $path = explode('/', $path);
        $keys = array_keys($path, '..');

        foreach($keys as $keypos => $key)
        {
            array_splice($path, $key - ($keypos * 2 + 1), 2);
        }

        $path = implode('/', $path);
        $path = str_replace('./', '', $path);

        $path = str_replace("//", "/", $path);

        if (empty($path)) return "/";
        return $path;
    }

    /**
     * @param $rawHeaders
     * @param $headersToSign
     * @return array
     */
    private static function canonicalizeHeaders($rawHeaders, array $headersToSign)
    {
        $result = array();
        foreach (explode("\n", $rawHeaders) as $header) {
            // TODO: add multiline header handling
            list ($key, $value) = explode(':', $header, 2);
            $lowerKey = strtolower($key);
            $trimmedValue = self::nomalizeHeaderValue($value);
            if (!in_array($lowerKey, $headersToSign)) {
                continue;
            }
            if (isset($result[$lowerKey])) {
                $result[$lowerKey] .= ',' . $trimmedValue;
            } else {
                $result[$lowerKey] =  $lowerKey . ':' . $trimmedValue;
            }
        }
        sort($result);
        return $result;
    }

    private static function rawUrlEncode($urlComponent)
    {
        $result = rawurlencode($urlComponent);
        if (version_compare(PHP_VERSION, '5.3.4') === -1) {
            $result = str_replace('%7E', '~', $result);
        }
        return $result;
    }

    /**
     * @param $value
     * @return string
     */
    private static function nomalizeHeaderValue($value)
    {
        $result = array();
        foreach (explode('"', trim($value)) as $index => $piece) {
            $result[] = $index % 2 === 1 ? $piece : preg_replace('/\s+/', ' ', $piece);
        }
        return implode('"', $result);
    }
}
