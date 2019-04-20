<?php

namespace Zer0\Brokers;

use Zer0\Config\Interfaces\ConfigInterface;

/**
 * Class CSRF_Token
 * @package Zer0\Brokers
 */
class CSRF_Token extends Base
{

    /**
     * @param ConfigInterface $config
     * @return \Zer0\Security\CSRF_Token
     */
    public function instantiate(ConfigInterface $config): \Zer0\Security\CSRF_Token
    {
        return new \Zer0\Security\CSRF_Token($config, $this->app->factory('HTTP'));
    }
    
    /**
     * @param string $name
     * @param bool $caching = true
     */
    public function get(string $name = '', bool $caching = true): \Zer0\Security\CSRF_Token
    {
        return parent::get($name, $caching);
    }
}
