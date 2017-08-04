<?php

namespace SilverStripe\Cow\Steps\Release;

use Exception;
use InvalidArgumentException;
use SilverStripe\Cow\Model\Release\Archive;
use SilverStripe\Cow\Utility\Composer;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Generate a new archive file for cms, framework in tar.gz and zip formats
 */
class BuildArchive extends PublishStep
{
    public function getStepName()
    {
        return 'release:archive';
    }

    public function run(InputInterface $input, OutputInterface $output)
    {
        // Get recipes and their versions to wait for
        $recipes = $this->getArchives($output);
        if (empty($recipes)) {
            $this->log($output, "No recipes configured for archive");
            return;
        };

        // Genreate all archives
        $count = count($recipes);
        $this->log($output, "Generating archives for {$count} recipes");
        foreach ($recipes as $recipe) {
            // Create project
            $path = $this->createProject($output, $recipe);
            foreach ($recipe->getFiles() as $file) {
                // Create file for this project
                $this->buildFiles($output, $path, $file);
            }
        }
        $this->log($output, 'Archive complete');
    }

    /**
     * Remove a directory and all subdirectories and files.
     *
     * @param string $folder Absolute folder path
     */
    protected function unlink($folder)
    {
        if (!file_exists($folder)) {
            return;
        }

        // remove a file encountered by a recursive call.
        if (is_file($folder) || is_link($folder)) {
            unlink($folder);
            return;
        }

        // Remove folder
        $dir = opendir($folder);
        while ($file = readdir($dir)) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            $this->unlink($folder . '/' . $file);
        }
        closedir($dir);
        rmdir($folder);
    }

    /**
     * Copy file
     *
     * @param string $from
     * @param string $to
     * @throws Exception
     */
    protected function copy($from, $to)
    {
        $this->unlink($to);

        // Copy file if not a folder
        if (!is_dir($from)) {
            if (copy($from, $to) === false) {
                throw new Exception("Could not copy from {$from} to {$to}");
            }
            return;
        }

        // Create destination
        if (mkdir($to) === false) {
            throw new Exception("Could not create destination folder {$to}");
        }

        // Iterate files
        $dir = opendir($from);
        while (false !== ($file = readdir($dir))) {
            if ($file == '.' || $file === '..') {
                continue;
            }
            $this->copy("{$from}/{$file}", "{$to}/{$file}");
        }
        closedir($dir);
    }

    /**
     * Write content to file
     *
     * @param string $path
     * @param string $content
     * @throws Exception
     */
    protected function write($path, $content)
    {
        $result = file_put_contents($path, $content);
        if ($result === false) {
            throw new Exception("Could not write to {$path}");
        }
    }

    /**
     * Build a project of the given version in a temporary folder, and return the path to this
     *
     * @param OutputInterface $output
     * @param Archive $archive
     * @return string Path to temporary project
     * @throws Exception
     */
    protected function createProject(OutputInterface $output, Archive $archive)
    {
        $name = $archive->getRelease()->getLibrary()->getName();
        $version = $archive->getRelease()->getVersion()->getValue();
        $path = $archive->getTempDir();
        $this->log($output, "Generating archives for <info>{$name}</info> at <comment>{$path}</comment>");

        // Ensure path is empty, but exists
        $this->unlink($path);
        if (!mkdir($path, 0777, true)) {
            throw new Exception("Could not create temp dir in $path");
        }

        // Install to this location
        $this->log($output, "Installing version {$version}");
        Composer::createProject($this->getCommandRunner($output), $name, $path, $version, null, true);

        // Copy composer.phar to the project
        // Write version info to the core folders (shouldn't be in version control)
        $this->log($output, "Including composer.phar");
        $this->copy('http://getcomposer.org/composer.phar', "{$path}/composer.phar");

        // Done
        return $path;
    }

    /**
     * Generate archives in each of the specified types from the temporary folder
     *
     * @param OutputInterface $output
     * @param string $path Location of project to archive
     * @param string $file File to generate
     */
    protected function buildFiles(OutputInterface $output, $path, $file)
    {
        $destination = $this->getProject()->getDirectory() . '/' . $file;
        $this->log($output, "Building <info>$destination</info>");

        // Build file command
        $sourgArg = escapeshellarg($path);
        $command = $this->getArchiveCommand($file);
        $destinationArg = escapeshellarg($destination);
        $this->runCommand($output, "cd {$sourgArg} && {$command} {$destinationArg} .");
    }

    /**
     * Get archive command
     *
     * @param string $file
     * @return string
     */
    protected function getArchiveCommand($file)
    {
        if (preg_match('/[.]zip$/', $file)) {
            return 'zip -rv';
        }
        if (preg_match('/[.]tar[.]gz$/', $file)) {
            return 'tar -cvzf';
        }
        throw new InvalidArgumentException("Cannot build archive for file {$file}");
    }
}
