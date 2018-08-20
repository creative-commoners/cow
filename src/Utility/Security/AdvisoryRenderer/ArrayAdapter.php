<?php
namespace SilverStripe\Cow\Utility\Security\AdvisoryRenderer;

class ArrayAdapter implements AdapterInterface
{
    /**
     * @param array $data
     * @return mixed
     */
    public function render(array $data)
    {
        return $data;
    }
}
