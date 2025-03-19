<?php

namespace SilverStripe\Cow\Model\Release;

use InvalidArgumentException;

class CommitHashVersion extends Version
{
    public static function parse($version)
    {
        // Note: Ignore leading 'v'
        $valid = preg_match(
            '/^[a-fA-F0-9]{40}$/',
            $version,
            $matches
        );
        if (!$valid) {
            return false;
        }
        return $matches;
    }

    public function __construct($version)
    {
        $matches = static::parse($version);
        if ($matches === false) {
            throw new InvalidArgumentException(
                "Invalid version $version. Expect SHA1 hash"
            );
        }
        $this->major = null;
        $this->minor = null;
        $this->patch = null;
        $this->stabilityVersion = null;
        $this->stability = null;
        $this->original = $version;
    }

    public function getValueStable()
    {
        return null;
    }

    /**
     * Get version string
     *
     * @return string
     */
    public function getValue()
    {
        return $this->original;
    }
}
