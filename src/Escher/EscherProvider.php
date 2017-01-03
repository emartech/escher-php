<?php

namespace Escher;


class EscherProvider
{
    private $credentialScope;
    private $escherKey;
    private $escherSecret;
    private $keyDB;

    public function __construct($credentialScope, $escherKey, $escherSecret, $keyDB)
    {
        $this->credentialScope = $credentialScope;
        $this->escherKey = $escherKey;
        $this->escherSecret = $escherSecret;
        $this->keyDB = $keyDB;
    }

    public function createEscher() : Escher
    {
        return Escher::create($this->credentialScope)
            ->setAlgoPrefix('EMS')
            ->setVendorKey('EMS')
            ->setAuthHeaderKey('X-Ems-Auth')
            ->setDateHeaderKey('X-Ems-Date');
    }

    public function getEscherKey() : string
    {
        return $this->escherKey;
    }

    public function getEscherSecret() : string
    {
        return $this->escherSecret;
    }

    /**
     * @return \ArrayAccess|array
     */
    public function getKeyDB()
    {
        return $this->keyDB;
    }
}

