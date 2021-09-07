<?php

namespace Escher;

use ArrayAccess;

class Provider
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

    /**
     * @return Escher
     */
    public function createEscher()
    {
        return Escher::create($this->credentialScope)
            ->setAlgoPrefix('EMS')
            ->setVendorKey('EMS')
            ->setAuthHeaderKey('X-Ems-Auth')
            ->setDateHeaderKey('X-Ems-Date');
    }


    /**
     * @return string
     */
    public function getEscherKey()
    {
        return $this->escherKey;
    }


    /**
     * @return string
     */
    public function getEscherSecret()
    {
        return $this->escherSecret;
    }

    /**
     * @return ArrayAccess|array
     */
    public function getKeyDB()
    {
        return $this->keyDB;
    }
}

