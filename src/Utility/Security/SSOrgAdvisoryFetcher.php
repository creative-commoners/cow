<?php
namespace SilverStripe\Cow\Utility\Security;

use DateTimeImmutable;
use DOMDocument;
use DOMNodeList;
use DOMXPath;
use SilverStripe\Cow\Model\Security\Advisory;

class SSOrgAdvisoryFetcher
{
    /**
     * @var string
     */
    protected $feedUrl;

    /**
     * SSOrgAdvisoryFetcher constructor.
     * @param string $feedUrl
     */
    public function __construct($feedUrl)
    {
        $this->feedUrl = $feedUrl;
    }

    public function getAdvisories(callable $onMissingAttribute = null, $limit = null)
    {
        $start = 0;
        $issues = [];

        do {
            $uri = $this->feedUrl . '?start=' . $start;
            $issues += $page = $this->parseUri($uri, $onMissingAttribute, $limit);
            $pageCount = count($page);

            if ($limit !== null) {
                $limit -= $pageCount;
            }

            $start += 15; // Fixed page-length on RSS feed...
        }
        while ($pageCount > 0 && ($limit === null || $limit > 0));

        return $issues;
    }

    protected function extractVersions(
        DOMNodeList $versionXpathContainer,
        $versionName,
        callable $onMissingAttribute,
        $advisoryContent
    ) {
        $content = null;

        // Hope the xpath node has something
        if ($versionXpathContainer->length) {
            $content = $versionXpathContainer->item(0)->textContent;
            // Strip any module name off the front
            if (preg_match('#^[a-z-]+/[a-z-]+:?#i', $content, $matches)) {
                $content = trim(substr($content, strlen($matches[0])));
            }
        }

        // Ask the user if we have nothing
        if (empty($content)) {
            $content = $onMissingAttribute($versionName, $advisoryContent, 'comma separated list');
        }

        // Split and parse...
        return array_map([$this, 'parseVersion'], explode(',', $content) ?: []);
    }

    /**
     * Handle some things like "3.5.5 and below"
     *
     * @param string $version
     * @return string
     */
    protected function parseVersion($version)
    {
        $version = trim($version);

        if (strpos($version, 'and below')) {
            $version = substr($version, 0, strpos($version, '.', strpos($version, '.') + 1)) . '.0';
        }

        if ($offset = strpos($version, ' to ')) {
            $version = substr($version, 0, $offset);
        }

        return preg_replace('/[^\d\.]+/', '' , $version);
    }

    protected function getIdentifierSources($link, callable $onMissingAttribute = null)
    {
        yield $link;
        yield $onMissingAttribute('identifier', $link);
    }

    protected function resolveSeverity($severity)
    {
        foreach ([
            Advisory::SEVERITY_CRITICAL,
            Advisory::SEVERITY_IMPORTANT,
            Advisory::SEVERITY_MODERATE,
            Advisory::SEVERITY_LOW,
        ] as $severityMatch) {
            if (stripos($severity, $severityMatch) === 0) {
                return $severityMatch;
            }
        }

        return Advisory::SEVERITY_UNKNOWN;
    }

    /**
     * @param $module
     * @param callable $onMissingAttribute
     * @param $limit
     * @param $xml
     * @param $matches
     * @return array
     * @throws \Exception
     */
    protected function parseUri($uri, callable $onMissingAttribute = null, $limit = null)
    {
        $xml = new DOMDocument('1.0');
        $xml->load($uri);
        $xpath = new DOMXPath($xml);

        $issues = [];
        foreach ($xpath->evaluate('//item') as $item) {
            // Pull the identifier from the link
            $identifier = null;
            $link = $xpath->evaluate('string(link)', $item);
            foreach ($this->getIdentifierSources($link, $onMissingAttribute) as $idSource) {
                if (preg_match('/SS-20\d{2}-\d{3,4}/i', $idSource, $matches)) {
                    $identifier = $matches[0];
                    break;
                }
            }
            if (!$identifier) {
                continue;
            }

            // Description is HTML too, re-parse it
            $descriptionDocument = new DOMDocument('1.0');
            $descriptionDocument->loadHTML($xpath->evaluate('string(description)', $item));
            $descriptionXpath = new DOMXPath($descriptionDocument);

            // Parse a description
            $severityXML = $descriptionDocument->saveXML();
            $rawDescription = substr($severityXML, strripos($severityXML, '</dl>'));
            $description = trim(html_entity_decode(strip_tags($rawDescription))) . PHP_EOL . $link;

            // Find the severity
            /** @var DOMNodeList $severityContainer */
            $severityContainer = $descriptionXpath->evaluate('//dd[1]');
            if ($severityContainer->length > 0) {
                $severity = $this->resolveSeverity($severityContainer->item(0)->textContent);
            } else {
                $severity = Advisory::SEVERITY_UNKNOWN;
            }

            // Affected Versions
            /** @var DOMNodeList $affectedVersionsContainer */
            $affectedVersionsContainer = $descriptionXpath->evaluate('//dd[3]');
            $affectedVersions = $this->extractVersions(
                $affectedVersionsContainer,
                'affected versions',
                $onMissingAttribute,
                $description
            );

            $fixedVersionsContainer = $descriptionXpath->evaluate('//dd[4]');
            $fixedVersions = $this->extractVersions(
                $fixedVersionsContainer,
                'fixed versions',
                $onMissingAttribute,
                $description
            );

            // Module
            $module = null;
            if ($affectedVersionsContainer->length) {
                $content = $affectedVersionsContainer->item(0)->textContent;
                if (preg_match('#^[a-z-]+/[a-z-]+:?#i', $content, $matches)) {
                    $module = trim(trim($matches[0]), ':');
                }
            }
            if (!$module) {
                $module = $onMissingAttribute('module name', $description, 'In composer:// format');
            }

            if (empty($module) || empty($affectedVersions) || empty($fixedVersions)) {
                continue;
            }

            $issues[$identifier] = new Advisory(
                $xpath->evaluate('string(title)', $item),
                $identifier,
                $module,
                $severity,
                $affectedVersions,
                $fixedVersions,
                new DateTimeImmutable($xpath->evaluate('string(pubDate)', $item)),
                $description
            );

            if ($limit && count($issues) >= $limit) {
                break;
            }
        }

        return $issues;
    }
}
