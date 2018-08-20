<?php
namespace SilverStripe\Cow\Utility\Security\AdvisoryRenderer;

use Symfony\Component\Yaml\Yaml;

class YamlAdapter implements AdapterInterface
{
    public function render(array $data)
    {
        return Yaml::dump($data, 3);
    }
}
