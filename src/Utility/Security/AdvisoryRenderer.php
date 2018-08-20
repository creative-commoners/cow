<?php
namespace SilverStripe\Cow\Utility\Security;

use DateTimeZone;
use Exception;
use SilverStripe\Cow\Model\Security\Advisory;
use SilverStripe\Cow\Utility\Security\AdvisoryRenderer\AdapterInterface;

class AdvisoryRenderer
{
    /**
     * @var AdapterInterface
     */
    protected $renderAdapter;

    const FORMAT_BASIC = 1;
    const FORMAT_SENSIO_REPOSITORY = 2;

    /**
     * @param AdapterInterface $renderAdapter
     */
    public function __construct(AdapterInterface $renderAdapter)
    {
        $this->renderAdapter = $renderAdapter;
    }

    /**
     * @param Advisory $advisory
     * @param int $format
     * @return mixed
     * @throws Exception
     */
    public function render(Advisory $advisory, $format = self::FORMAT_BASIC)
    {
        switch ($format) {
            case self::FORMAT_BASIC:
                return $this->renderAdapter->render($this->toBasicArray($advisory));
            case self::FORMAT_SENSIO_REPOSITORY:
                return $this->renderAdapter->render($this->toSensioArray($advisory));
        }

        throw new Exception('Unsupported output format provided');
    }

    /**
     * @param Advisory $advisory
     * @return array
     */
    protected function toBasicArray(Advisory $advisory)
    {
        return [
            'title' => $advisory->getTitle(),
            'identifier' => $advisory->getIdentifier(),
            'module' => $advisory->getModule(),
            'severity' => $advisory->getSeverity(),
            'affectedVersions' => $advisory->getAffectedVersions(),
            'fixedVersions' => $advisory->getFixedVersions(),
            'releaseDate' => $advisory->getReleaseDate(),
            'description' => $advisory->getDescription(),
        ];
    }

    /**
     * @param Advisory $advisory
     * @return array
     */
    protected function toSensioArray(Advisory $advisory)
    {
        $output = [
            'title' => $advisory->getTitle(),
            'link' => Advisory::LINK_BASE . urlencode(strtolower($advisory->getIdentifier())),
            'cve' => '~',
            'branches' => [],
            'reference' => 'composer://' . $advisory->getModule(),
        ];

        // Run through fixed versions to list branches
        foreach ($advisory->getFixedVersions() as $version) {
            // Exclude versions that end in '.0.0' - this implies the whole major version is fine
            if (substr($version, -4) === '.0.0') {
                continue;
            }

            // If the version ends in .0 - we're dealing with a vulnerability that is fixed in a minor release - base
            // branch will be "version.x"
            $isMinor = substr($version, -2) === '.0';
            $major = substr($version, 0, strpos($version, '.'));

            // If we're a minor but we've already parsed some branches (of the same major release) then there's no point
            // listing fixed minor releases
            if (
                $isMinor && !empty($output['branches']) &&
                $this->findInArray($output['branches'], function ($branchData, $branch) use ($major) {
                    return $major === substr($branch, 0, strpos($branch, '.'));
                })
            ) {
                continue;
            }

            $toVersion = $version;
            $branch = $isMinor
                ? $major
                : substr($version, 0, strrpos($version, '.'));

            // Attempt to find an affected version that has the same parent version
            $fromVersion = $this->findInArray($advisory->getAffectedVersions(), function($version) use ($branch) {
                $version = preg_replace('/[^\d.]/', '', $version);
                if (strpos($version, $branch) === 0) {
                    return true;
                }
                return false;
            });

            if (!$fromVersion) {
                continue;
            }

            $output['branches'][$branch . '.x'] = [
                'time' => $advisory->getReleaseDate()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
                'versions' => ['>=' . $fromVersion, '<' . $toVersion],
            ];
        }

        return $output;
    }

    protected function findInArray(array $array, callable $filter)
    {
        foreach ($array as $key => $item) {
            if ($filter($item, $key)) {
                return $item;
            }
        }

        return null;
    }
}
