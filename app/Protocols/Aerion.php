<?php

namespace App\Protocols;

use App\Models\Server;
use App\Support\AbstractProtocol;
use App\Support\YamlSubscription;

class Aerion extends AbstractProtocol
{
    use YamlSubscription;

    public $flags = ['aerion', 'xbclient', 'neto'];

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
    ];
}
