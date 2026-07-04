<?php

namespace App\Protocols;

use App\Utils\Helper;

class Nekobox
{
    public $flag = 'nekobox';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $uri = '';

        foreach ($this->servers as $server) {
            if (($server['type'] ?? null) === 'v2node' && ($server['protocol'] ?? null) === 'shadowtls') {
                $uri .= Helper::buildNekoboxShadowtlsUri($this->user['uuid'], $server);
                continue;
            }
            $uri .= Helper::buildUri($this->user['uuid'], $server);
        }

        return base64_encode($uri);
    }
}
