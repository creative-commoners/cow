<?php

namespace SilverStripe\Cow\Commands\Security;

use DateTime;
use Exception;
use Gitonomy\Git\Admin;
use Gitonomy\Git\Exception\ProcessException;
use Gitonomy\Git\Repository;
use SilverStripe\Cow\Commands\Command;
use SilverStripe\Cow\Model\Security\Advisory;
use SilverStripe\Cow\Utility\Config;
use SilverStripe\Cow\Utility\Security\AdvisoryRenderer;
use SilverStripe\Cow\Utility\Security\GitAdvisoryFetcher;
use SilverStripe\Cow\Utility\Security\SSOrgAdvisoryFetcher;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\Output;
use Symfony\Component\Console\Question\Question;

class SyncIssues extends Command
{
    const DEFAULT_REPO = 'https://github.com/FriendsOfPHP/security-advisories';
    const DEFAULT_HEAD = 'https://github.com/creative-commoners/security-advisories';

    /**
     * @var string
     */
    protected $name = "security:sync-issues";

    /**
     * @var string
     */
    protected $description = 'Pull security advisories from silverstripe.org and generate a PR to sync them with security.sensiolabs.org';

    protected function configureOptions()
    {
        $this
            ->addOption(
                'limit',
                'l',
                InputOption::VALUE_REQUIRED,
                'Limit the number of advisories parsed from SilverStripe.org'
            )
            ->addOption(
                'base-repo',
                'b',
                InputOption::VALUE_REQUIRED,
                'The base repository to fetch advisories from and make a PR against. Defaults to SensioLabs.',
                self::DEFAULT_REPO
            )
            ->addOption(
                'make-pull-request',
                'p',
                InputOption::VALUE_NONE,
                'Make a pull request to the base repository. Requires "hub" installed'
            )
            ->addOption(
                'head-repo',
                'H',
                InputOption::VALUE_REQUIRED,
                'The head repository to base pull request when using the -pr option',
                self::DEFAULT_HEAD
            )
            ->addOption(
                'repository-dir',
                'd',
                InputOption::VALUE_REQUIRED,
                'Specify a directory where the SensioLabs repository is (or should be created)'
            )
            ->addOption(
                'pr-message',
                'm',
                InputOption::VALUE_REQUIRED,
                'Provide a message in the hub pull-request format to add to the PR'
            );
    }

    /**
     * {@inheritdoc}
     */
    protected function fire()
    {
        // Validate the request to make a PR
        $makePR = $this->input->getOption('make-pull-request');

        if ($makePR) {
            exec('hub --version', $output);
            if (!isset($output[1]) || strpos($output[1], 'hub') === false) {
                throw new Exception(
                    'Could not find "hub" installed. For PR support please ensure hub is installed.' . PHP_EOL .
                    'Hub is available on brew (brew install hub) or available at https://github.com/github/hub'
                );
            }
        }

        $repository = $this->getRepository();

        $gitAdvisoryFetcher = new GitAdvisoryFetcher($repository);
        $repoAdvisories = $gitAdvisoryFetcher->getAdvisories('*', '*', [$this, 'onMissingRepoAttribute']);

        $limit = $this->input->getOption('limit');
        if ($limit !== null) {
            $limit = is_numeric($limit) ? (int) $limit : null;
        }

        $ssOrgAdvisoryFetcher = new SSOrgAdvisoryFetcher('https://www.silverstripe.org/download/security-releases/rss');
        $ssOrgAdvisories = $ssOrgAdvisoryFetcher->getAdvisories([$this, 'onMissingRepoAttribute'], $limit);

        // Find unsynced advisories
        /** @var Advisory[] $unsynced */
        $unsynced = array_diff_key($ssOrgAdvisories, $repoAdvisories);
        $renderer = new AdvisoryRenderer(new AdvisoryRenderer\YamlAdapter());

        // Run though and create files for the advisories
        foreach ($unsynced as $advisory) {
            $this->touchDirectory($repository->getPath(), $advisory->getModule());
            $directory = $repository->getPath() . DIRECTORY_SEPARATOR . $advisory->getModule();

            $file = $directory . DIRECTORY_SEPARATOR . $advisory->getIdentifier() . '.yaml';
            file_put_contents(
                $file,
                $renderer->render($advisory, AdvisoryRenderer::FORMAT_SENSIO_REPOSITORY)
            );
            // Add the file to the repo
            if ($makePR) {
                $repository->run('add', [$file]);
            }

            $this->output->writeln('<info> - Parsed ' . $advisory->getIdentifier() . '</info>');
        }

        // If we're making a PR...
        if ($makePR) {
            $this->makePullRequest($repository);
        }
    }

    public function onMissingRepoAttribute($attributeName, $knownData, $formatting = null)
    {
        /** @var QuestionHelper $questionHelper */
        $questionHelper = $this->getHelper('question');

        return $questionHelper->ask($this->input, $this->output, new Question(
            '<comment>Attempting to resolve advisory from data, but cannot determine a valid ' . $attributeName .
            ':</comment>' . PHP_EOL . $knownData . PHP_EOL . '<comment>Can you provide the ' . $attributeName . '? ' .
            ( !empty($formatting) ? '(' . $formatting . ') ' : '' ) . '</comment>'
        ));
    }

    protected function makePullRequest(Repository $repository)
    {
        // Add the "head" repo
        $head = $this->input->getOption('head-repo');
        if (!($headName = $this->findRemote($repository, $head))) {
            $headName = 'cow-sync-head';
            $repository->run('remote', ['add', 'cow-sync-head', $head]);
        }

        // Create a branch
        $date = new DateTime();
        $output = $repository->run('branch');
        $branchName = 'add-advisories-' . strtolower($date->format('M-Y'));
        $args = [$branchName,]; //  '-t', $headName . '/master'
        if (!preg_match('/'.$branchName.'$/im', $output)) {
            array_unshift($args, '-b');
        }
        $repository->run('checkout', $args);

        // Run the validator...
        $this->output->writeln('<comment>Running advisory validator... (This may take a while)</comment>');

        $cwd = getcwd();
        chdir($repository->getPath());
        exec('php -d memory_limit=1G ' . 'validator.php -g', $output);
        chdir($cwd);

        $status = null;
        while (!empty($output)) {
            $line = array_shift($output);

            // Look for "OK" and continue...
            if (strpos($line, '[OK]') !== false) {
                break;
            }

            // If we find "ERROR" - we should output the problem and abandon the PR
            if (strpos($line, '[ERROR]') !== false) {
                $this->output->writeln(
                    '<error>There are some issues with the added advisories. Please correct them and manually ' .
                    'submit a PR</error>'
                );
                $this->output->writeln(implode(PHP_EOL, array_filter($output)), Output::OUTPUT_RAW);

                return;
            }
        }

        // Commit the advisories
        $repository->run('config', ['user.email', 'guy@scopey.co.nz']);
        $repository->run('config', ['user.name', 'Guy Marriott']);
        $repository->run('commit', [
            '-m', 'Adding advisories for SilverStripe and supported sub-modules',
            '--author', 'Guy Marriott <guy@scopey.co.nz>'
        ]);
        $repository->run('push', [$headName]);

        $message = $this->input->getOption('pr-message') ?: '"Add latest SilverStripe advisories' . PHP_EOL .
            PHP_EOL . 'This PR adds the latest advisories fixed in SilverStripe (supported) modules: ' .
            'https://www.silverstripe.org/download/security-releases/"';

        // Run hub PR
        $base = $this->input->getOption('base-repo');
        $hubArguments = [
            '-b', $this->parseRepo($base) . ':master',
            '-h', $this->parseRepo($head) . ':' . $branchName,
            '-m', $message
        ];

        $cwd = getcwd();
        chdir($repository->getPath());
        exec('hub pull-request ' . implode(' ', $hubArguments), $output);
        chdir($cwd);

        $output = array_filter($output);
        $this->output->writeln('Done! PR at '.reset($output));

    }

    protected function cleanOutput($outputString)
    {
        return str_replace(['\t', '\n'], ["\t", "\n"], $outputString);
    }

    protected function touchDirectory($base, $folder)
    {
        $folders = explode(DIRECTORY_SEPARATOR, $folder);

        $currentFolder = $base . DIRECTORY_SEPARATOR;
        foreach ($folders as $folder) {
            $currentFolder .= $folder . DIRECTORY_SEPARATOR;
            if (!file_exists($currentFolder)) {
                mkdir($currentFolder, 0755);
            }
        }
    }

    protected function parseRepo($repoUrl)
    {
        preg_match('/[^@\/]+(?:@|\/\/)(?:www\.)?github.com(?:\/|:)([^\s.]+)/i', $repoUrl, $matches);

        return $matches[1];
    }

    /**
     * @return Repository|null
     * @throws Exception
     */
    public function getRepository()
    {
        $remote = $this->input->getOption('base-repo');
        $directory = $this->input->getOption('repository-dir') ?: $this->getTempDirectory($remote);

        $options = [];
        if ($this->input->getOption('make-pull-request')) {
            $options['command'] = 'hub';
            $options['environment_variables'] = [
                'HOME' => getenv('HOME'),
                'PATH' => getenv('PATH')
            ];
        }

        // Attempt to find an existing repo in the tmp directory
        $repository = null;
        if (is_dir($directory)) {
            $repository = new Repository($directory, $options);
            if (!$this->prepareExistingRepository($repository, $remote)) {
                throw new Exception('A git repository already exists at "' . $directory . '" but it does not ' .
                    'appear to be a sensiolabs/security-advisories repository');
            }
        }

        if (!$repository) {
            $repository = Admin::cloneRepository($directory, $remote, [], $options);
        }

        return $repository;
    }

    /**
     * "Prepare" a given repository, finding an appropriate remote and fetching it, or adding the remote to the
     * repository provided the repository appears to be valid.
     *
     * @param Repository $repository
     * @param string $remoteRepo
     * @return bool Returns false if the given repository could not be "prepared"
     */
    protected function prepareExistingRepository(Repository $repository, $remoteRepo)
    {
        $remote = $this->findRemote($repository, $remoteRepo);

        if (!$remote) {
            // Attempt to see if it's the same project...
            $composer = $this->getTempDirectory($remoteRepo) . DIRECTORY_SEPARATOR . 'composer.json';

            if (!file_exists($composer)) {
                return false;
            }

            try {
                $composer = Config::parseContent(file_get_contents($composer));
            } catch (Exception $exception) {
                // Whatever's the issue here, the existing repo is not valid...
                return false;
            }

            if (!isset($composer['name']) || $composer['name'] !== 'sensiolabs/security-advisories') {
                return false;
            }

            $remote = 'cow-sync-repo';

            try {
                $repository->run('remote', ['add', $remote, $remoteRepo]);
            } catch (ProcessException $e) {
                return false;
            }
        }

        $repository->run('fetch', [$remote]);

        return true;
    }

    /**
     * @param string $remoteRepo
     * @return string
     */
    protected function getTempDirectory($remoteRepo)
    {
        return sys_get_temp_dir() . substr(
                $remoteRepo,
                strrpos($remoteRepo, '/')
            );
    }

    /**
     * Find the `$this->advisoryRemote` name in the given git repository
     *
     * @param Repository $repository
     * @param string $remoteRepo
     * @return false|string
     */
    protected function findRemote(Repository $repository, $remoteRepo)
    {
        $rawRemotes = $repository->run('remote', ['-v']);
        $remotes = [];

        $pattern = '/^(?<name>[^\t]+)\t(?<uri>[^\s]+)/';
        foreach (array_filter(explode(PHP_EOL, $rawRemotes)) as $rawRemote) {
            if (preg_match($pattern, $rawRemote, $matches)) {
                $name = $matches['name'];
                $uri = $matches['uri'];

                if ($remoteRepo === $uri || $remoteRepo === str_replace('git@github.com:', 'https://github.com/', $uri)) {
                    return $name;
                }
            }
        }

        return false;
    }
}
