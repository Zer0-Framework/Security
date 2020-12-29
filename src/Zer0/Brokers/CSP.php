<?php

namespace Zer0\Brokers;

use Zer0\Config\Interfaces\ConfigInterface;

/**
 * Class CSP
 * @package Zer0\Brokers
 */
class CSP extends Base
{

    /**
     * @param ConfigInterface $config
     * @return \Zer0\Security\CSRF_Token
     */
    public function instantiate(ConfigInterface $config): \Zer0\Security\CSP
    {
        return new \Zer0\Security\CSP($config, $this->app->factory('HTTP'));
    }
}
