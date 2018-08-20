<?php
namespace SilverStripe\Cow\Utility\Security\AdvisoryRenderer;

interface AdapterInterface
{
    /**
     * @param array $data
     * @return mixed
     */
    public function render(array $data);
}
