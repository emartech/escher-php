<?php

namespace Escher;


class Utils
{
    public static function parseLongDate($dateString)
    {
        if (!preg_match('/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/', $dateString)) {
            throw new Exception('Date header is invalid, the expected format is 20151104T092022Z', Exception::CODE_FORMAT_INVALID_DATE_HEADER);
        }
        if (!self::advancedDateTimeFunctionsAvailable()) {
            return new \DateTime($dateString, new \DateTimeZone('GMT'));
        }
        return \DateTime::createFromFormat('Ymd\THisT', $dateString, new \DateTimeZone('GMT'));
    }

    public static function keysToLower($array)
    {
        if (count($array) === 0)
        {
            return array();
        }
        return array_combine(
            array_map('strtolower', array_keys($array)),
            array_values($array)
        );
    }

    public static function getTimeStampOfDateTime($dateTime)
    {
        if (!self::advancedDateTimeFunctionsAvailable()) {
            return $dateTime->format('U');
        }
        return $dateTime->getTimestamp();
    }

    /**
     * @return bool
     */
    protected static function advancedDateTimeFunctionsAvailable()
    {
        return version_compare(PHP_VERSION, '5.3.0') !== -1;
    }
}
