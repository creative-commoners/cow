<?php
namespace SilverStripe\Cow\Model\Security;

use DateTimeImmutable;
use Symfony\Component\Yaml\Yaml;

class Advisory
{
    const LINK_BASE = 'https://www.silverstripe.org/download/security-releases/';

    const SEVERITY_CRITICAL = 'Critical';
    const SEVERITY_IMPORTANT = 'Important';
    const SEVERITY_MODERATE = 'Moderate';
    const SEVERITY_LOW = 'Low';
    const SEVERITY_UNKNOWN = 'Unknown';

    /**
     * @var string
     */
    protected $title;

    /**
     * @var string
     */
    protected $identifier;

    /**
     * @var string
     */
    protected $module;

    /**
     * @var string (One of the SEVERITY_ constants)
     */
    protected $severity;

    /**
     * @var string[]
     */
    protected $affectedVersions;

    /**
     * @var string[]
     */
    protected $fixedVersions;

    /**
     * @var DateTimeImmutable
     */
    protected $releaseDate;

    /**
     * @var string
     */
    protected $description;

    /**
     * @param string $title
     * @param string $identifier
     * @param string $module
     * @param string $severity
     * @param string[] $affectedVersions
     * @param string[] $fixedVersions
     * @param DateTimeImmutable $releaseDate
     * @param string $description
     */
    public function __construct(
        $title,
        $identifier,
        $module,
        $severity,
        array $affectedVersions,
        array $fixedVersions,
        DateTimeImmutable $releaseDate,
        $description
    ) {
        $this->title = $title;
        $this->identifier = $identifier;
        $this->module = $module;
        $this->severity = $severity;
        $this->affectedVersions = $affectedVersions;
        $this->fixedVersions = $fixedVersions;
        $this->releaseDate = $releaseDate;
        $this->description = $description;
    }

    /**
     * @return string
     */
    public function getTitle()
    {
        return $this->title;
    }

    /**
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    public function getModule()
    {
        return $this->module;
    }

    /**
     * @return string
     */
    public function getSeverity()
    {
        return $this->severity;
    }

    /**
     * @return string[]
     */
    public function getAffectedVersions()
    {
        return $this->affectedVersions;
    }

    /**
     * @return string[]
     */
    public function getFixedVersions()
    {
        return $this->fixedVersions;
    }

    /**
     * @return DateTimeImmutable
     */
    public function getReleaseDate()
    {
        return $this->releaseDate;
    }

    /**
     * @return string
     */
    public function getDescription()
    {
        return $this->description;
    }
}
