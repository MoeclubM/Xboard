<?php

namespace App\Protocols;

use App\Models\Server;
use App\Support\FluxConfig;

class Aerion extends ClashMeta
{
    public $flags = ['aerion', 'xbclient'];

    protected $protocolRequirements = [];

    public $allowedProtocols = [
        Server::TYPE_SHADOWSOCKS,
        Server::TYPE_VMESS,
        Server::TYPE_TROJAN,
        Server::TYPE_VLESS,
        Server::TYPE_HYSTERIA,
        Server::TYPE_TUIC,
        Server::TYPE_ANYTLS,
        Server::TYPE_SOCKS,
        Server::TYPE_HTTP,
        Server::TYPE_MIERU,
        Server::TYPE_SUDOKU,
        Server::TYPE_FLUX,
    ];

    protected function filterServersByVersion()
    {
        $this->filterByAllowedProtocols();
        $supportsFlux = FluxConfig::supportsClient(request(), $this->userAgent ?? '', 'aerion');
        return array_values(array_filter($this->servers,
            fn($server) => $server['type'] !== Server::TYPE_FLUX || $supportsFlux));
    }

    protected function buildProxy(array $server): ?array
    {
        return $server['type'] === Server::TYPE_FLUX
            ? FluxConfig::toClientProxy((string) $server['password'], $server)
            : parent::buildProxy($server);
    }
}
