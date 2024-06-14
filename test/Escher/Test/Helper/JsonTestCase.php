<?php

namespace Escher\Test\Helper;

use DateTime;
use DateTimeZone;

class JsonTestCase
{
    /**
     * @var array
     */
    private $data;
    /**
     * @var string
     */
    public $suite;
    /**
     * @var string
     */
    public $type;
    /**
     * @var string
     */
    public $name;

    public static function getTestCases(string $type): array
    {
        $dir = new \RecursiveDirectoryIterator(__DIR__ . '/../../../../test-cases/');
        $iterator = new \RecursiveIteratorIterator($dir);
        $matches = new \RegexIterator($iterator, '#^.*/test-cases/(?P<suite>[^/]+)/(?P<type>[^-]+)-(?P<name>[^.]+)\.json$#', \RegexIterator::GET_MATCH);

        $cases = [];
        foreach ($matches as $match) {
            if ($match['type'] !== $type) {
                continue;
            }
            if ($match['suite'] === '.conflict') {
                continue;
            }
            $cases[] = new JsonTestCase($match[0], $match['suite'], $match['type'], $match['name']);
        }

        return $cases;
    }

    public function __construct(string $path, string $suite, string $type, string $name)
    {
        $this->suite = $suite;
        $this->type = $type;
        $this->name = $name;

        $this->data = json_decode(file_get_contents($path), true);
    }

    public function getCredentialScope(): string
    {
        return $this->data['config']['credentialScope'];
    }

    public function getHeadersToSign(): array
    {
        return $this->data['headersToSign'];
    }

    public function getRequest(): array
    {
        $request = $this->data['request'];
        $request['headers'] = [];
        foreach ($this->data['request']['headers'] ?? [] as $h) {
            $request['headers'][$h[0]] = $h[1];
        }

        return $request;
    }

    public function hasExpectedCanonicalizedRequest(): bool
    {
        return array_key_exists('canonicalizedRequest', $this->data['expected']);
    }

    public function hasExpectedStringToSign(): bool
    {
        return array_key_exists('stringToSign', $this->data['expected']);
    }

    public function hasExpectedHeaders(): bool
    {
        return array_key_exists('request', $this->data['expected']);
    }

    public function hasExpectedApiKey(): bool
    {
        return array_key_exists('apiKey', $this->data['expected']);
    }

    public function hasExpectedError(): bool
    {
        return array_key_exists('error', $this->data['expected']);
    }

    public function getExpectedCanonicalizedRequest(): string
    {
        return $this->data['expected']['canonicalizedRequest'];
    }

    public function getExpectedStringToSign(): string
    {
        return $this->data['expected']['stringToSign'];
    }

    public function getExpectedHeaders(): array
    {
        $headers = [];
        foreach ($this->data['expected']['request']['headers'] ?: [] as $h) {
            $headers[strtolower($h[0])] = $h[1];
        }
        return $headers;
    }

    public function getExpectedUrl(): string
    {
        return $this->data['expected']['url'];
    }

    public function getExpectedApiKey(): string
    {
        return $this->data['expected']['apiKey'];
    }

    public function getExpectedError(): string
    {
        return $this->data['expected']['error'];
    }

    public function getMandatorySignedHeaders()
    {
        return $this->data['mandatorySignedHeaders'] ?? [];
    }

    public function getAlgoPrefix(): string
    {
        return $this->data['config']['algoPrefix'];
    }

    public function getVendorKey(): string
    {
        return $this->data['config']['vendorKey'];
    }

    public function getHashAlgo(): string
    {
        return $this->data['config']['hashAlgo'];
    }

    public function getAuthHeaderName(): ?string
    {
        return $this->data['config']['authHeaderName'] ?? null;
    }

    public function getDateHeaderName(): ?string
    {
        return $this->data['config']['dateHeaderName'] ?? null;
    }

    public function getApiKey(): string
    {
        return $this->data['config']['accessKeyId'];
    }

    public function getApiSecret(): ?string
    {
        return $this->data['config']['apiSecret'] ?? null;
    }

    public function getKeyDb(): array
    {
        $keyDb = [];
        foreach ($this->data['keyDb'] as $v) {
            $keyDb[$v[0]] = $v[1];
        }
        return $keyDb;
    }

    public function getCurrentTime(): DateTime
    {
        $timeFormats = ['Y-m-d\TH:i:s.000Z', 'Y-m-d\TH:i:s\Z', 'l, d M Y H:i:s \G\M\T'];

        foreach ($timeFormats as $format) {
            $currentTime = DateTime::createFromFormat($format, $this->data['config']['date'], new DateTimeZone('UTC'));
            if ($currentTime) {
                return $currentTime;
            }
        }

        throw new \Exception("Invalid time => {$this->data['config']['date']}");
    }
}
