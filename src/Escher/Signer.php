<?php

namespace Escher;


class Signer
{
    public static function createStringToSign($credentialScope, $canonicalRequestString, \DateTime $date, $hashAlgo, $algoPrefix)
    {
        $date = clone $date;
        $date->setTimezone(new \DateTimeZone("GMT"));
        $formattedDate = $date->format(Escher::LONG_DATE);
        $scope = substr($formattedDate,0, 8) . "/" . $credentialScope;
        $lines = array();
        $lines[] = $algoPrefix . "-HMAC-" . strtoupper($hashAlgo);
        $lines[] = $formattedDate;
        $lines[] = $scope;
        $lines[] = hash($hashAlgo, $canonicalRequestString);
        return implode("\n", $lines);
    }

    public static function calculateSigningKey($secret, $credentialScope, $hashAlgo, $algoPrefix)
    {
        $key = $algoPrefix . $secret;
        $credentials = explode("/", $credentialScope);
        foreach ($credentials as $data) {
            $key = hash_hmac($hashAlgo, $data, $key, true);
        }
        return $key;
    }

    public static function createAuthHeader($signature, $credentialScope, $signedHeaders, $hashAlgo, $algoPrefix, $accessKey)
    {
        return $algoPrefix . "-HMAC-" . strtoupper($hashAlgo)
        . " Credential="
        . $accessKey . "/"
        . $credentialScope
        . ", SignedHeaders=" . $signedHeaders
        . ", Signature=" . $signature;
    }

    public static function createSignature($stringToSign, $signerKey, $hashAlgo)
    {
        return hash_hmac($hashAlgo, $stringToSign, $signerKey);
    }
}
