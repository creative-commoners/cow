<?php
namespace SilverStripe\Cow\Utility\Security;

use DateTimeImmutable;
use Exception;
use Generator;
use Gitonomy\Git\Admin;
use Gitonomy\Git\Exception\ProcessException;
use Gitonomy\Git\Repository;
use SilverStripe\Cow\Model\Security\Advisory;
use SilverStripe\Cow\Utility\Config;
use Symfony\Component\Yaml\Yaml;

class GitAdvisoryFetcher
{
    /**
     * @var Repository
     */
    protected $repository;

    /**
     * @param Repository $repository
     */
    public function __construct(Repository $repository)
    {
        $this->repository = $repository;
    }

    public function getAdvisories($vendor = '*', $module = '*', callable $onMissingAttribute = null)
    {
        $files = glob(implode(DIRECTORY_SEPARATOR, [$this->repository->getPath(), $module, $vendor, 'SS-20??-*.*']));
        $advisories = [];

        foreach ($files as $file) {
            $parsedData = Yaml::parseFile($file);

            // Find the identifier from several sources
            $identifier = null;
            foreach ($this->getIdentifierSources($parsedData, $file, $onMissingAttribute) as $idSource) {
                if (preg_match('/SS-20\d{2}-\d{3,4}/i', $idSource, $matches)) {
                    $identifier = strtoupper($matches[0]);
                    break;
                }
            }
            if (!$identifier) {
                continue;
            }

            $advisories[$identifier] = new Advisory(
                $parsedData['title'],
                $identifier,
                substr($parsedData['reference'], 11), // Strip composer://
                Advisory::SEVERITY_UNKNOWN,
                [],
                [],
                new DateTimeImmutable(),
                ''
            );
        }

        return $advisories;
    }

    /**
     * @param $advisoryData
     * @param $fileName
     * @param callable|null $onMissingAttribute
     * @return Generator
     */
    protected function getIdentifierSources($advisoryData, $fileName, callable $onMissingAttribute = null)
    {
        yield $advisoryData['link'];
        yield $advisoryData['title'];
        yield $fileName;
        yield $onMissingAttribute('identifier', Yaml::dump($advisoryData));
    }
}
