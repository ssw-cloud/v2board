<?php

namespace App\Protocols;

use App\Utils\Helper;

class V2rayNG
{
    public $flag = 'v2rayng';
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
            if (($server['type'] ?? null) === 'v2node' && ($server['protocol'] ?? null) === 'naive') {
                $uri .= Helper::buildNaiveV2rayNUri($this->user['uuid'], $server);
            } else {
                $uri .= Helper::buildUri($this->user['uuid'], $server);
            }
        }
        return base64_encode($uri);
    }
}
