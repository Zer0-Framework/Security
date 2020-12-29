<?php


namespace Zer0\Security;


use Zer0\Config\Interfaces\ConfigInterface;
use Zer0\Helpers\Str;
use Zer0\HTTP\HTTP;

/**
 * Class CSP
 * @package Zer0\Security
 */
class CSP
{

    /**
     * @var ConfigInterface
     */
    protected $config;

    /**
     * @var HTTP
     */
    protected $http;

    /**
     * CSP constructor.
     * @param ConfigInterface $config
     * @param HTTP $http
     */
    public function __construct(ConfigInterface $config, HTTP $http)
    {
        $this->config = $config;
        $this->http = $http;
    }


    /**
     * @return string
     * @throws \Exception
     */
    protected function generateNonce(): string
    {
        return Str::base64UrlEncode(random_bytes(12));
    }

    /**
     *
     */
    public function sendHeader(): void
    {
        $header = 'Content-Security-Policy:';
        foreach ($this->config->src as $category => $settings) {
            $header .= ' ' . $category . '-src';
            if ($settings['self'] ?? false) {
                $header .= ' \'self\'';
            }
            if ($settings['unsafe-inline'] ?? false) {
                $header .= ' \'unsafe-inline\'';
            }
            if ($settings['nonce'] ?? false) {
                $_SERVER['CSP_NONCE'] = $_SERVER['CSP_NONCE'] ?? $this->generateNonce();
                $header .= ' \'nonce-' . $_SERVER['CSP_NONCE'] . '\'';
            }
            foreach ($settings['domains'] ?? [] as $domain) {
                $header .= ' ' . str_replace('$host', $_SERVER['HTTP_HOST'], $domain);
            }
            $header .= ';';
        }
        $this->http->header('default-src \'self\'; img-src *; media-src *; script-src $host \'unsafe-inline\'');
    }
}
