<?php

namespace App\Support;

use App\Models\Server;
use App\Protocols\ClashMeta;
use Symfony\Component\Yaml\Yaml;

trait YamlSubscription
{
    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;
        $appName = admin_setting('app_name', 'XBoard');

        $template = subscribe_template('clashmeta');

        $config = Yaml::parse($template);
        $proxy = [];
        $proxies = [];

        foreach ($servers as $item) {
            if (($entry = $this->buildProxy($item)) !== null) {
                $proxy[] = $entry;
                $proxies[] = $item['name'];
            }
        }

        $config['proxies'] = array_merge($config['proxies'] ? $config['proxies'] : [], $proxy);
        foreach ($config['proxy-groups'] as $k => $v) {
            if (!is_array($config['proxy-groups'][$k]['proxies']))
                $config['proxy-groups'][$k]['proxies'] = [];
            $isFilter = false;
            foreach ($config['proxy-groups'][$k]['proxies'] as $src) {
                foreach ($proxies as $dst) {
                    if (!$this->isRegex($src))
                        continue;
                    $isFilter = true;
                    $config['proxy-groups'][$k]['proxies'] = array_values(array_diff($config['proxy-groups'][$k]['proxies'], [$src]));
                    if ($this->isMatch($src, $dst)) {
                        array_push($config['proxy-groups'][$k]['proxies'], $dst);
                    }
                }
                if ($isFilter)
                    continue;
            }
            if ($isFilter)
                continue;
            $config['proxy-groups'][$k]['proxies'] = array_merge($config['proxy-groups'][$k]['proxies'], $proxies);
        }
        $config['proxy-groups'] = array_filter($config['proxy-groups'], function ($group) {
            return $group['proxies'];
        });
        $config['proxy-groups'] = array_values($config['proxy-groups']);
        $config = $this->buildRules($config);

        $yaml = Yaml::dump($config, 2, 4, Yaml::DUMP_EMPTY_ARRAY_AS_SEQUENCE);
        $yaml = str_replace('$app_name', admin_setting('app_name', 'XBoard'), $yaml);
        return response($yaml)
            ->header('content-type', 'text/yaml')
            ->header('subscription-userinfo', "upload={$user['u']}; download={$user['d']}; total={$user['transfer_enable']}; expire={$user['expired_at']}")
            ->header('profile-update-interval', '24')
            ->header('content-disposition', 'attachment;filename*=UTF-8\'\'' . rawurlencode($appName));
    }

    protected function buildProxy(array $server): ?array
    {
        $password = $server['password'];
        return match ($server['type']) {
            Server::TYPE_SHADOWSOCKS => ClashMeta::buildShadowsocks($password, $server),
            Server::TYPE_VMESS => ClashMeta::buildVmess($password, $server),
            Server::TYPE_TROJAN => ClashMeta::buildTrojan($password, $server),
            Server::TYPE_VLESS => ClashMeta::buildVless($password, $server),
            Server::TYPE_HYSTERIA => ClashMeta::buildHysteria($password, $server, $this->user),
            Server::TYPE_TUIC => ClashMeta::buildTuic($password, $server),
            Server::TYPE_ANYTLS => ClashMeta::buildAnyTLS($password, $server),
            Server::TYPE_SOCKS => ClashMeta::buildSocks5($password, $server),
            Server::TYPE_HTTP => ClashMeta::buildHttp($password, $server),
            Server::TYPE_SUDOKU => ClashMeta::buildSudoku($password, $server),
            Server::TYPE_MIERU => ClashMeta::buildMieru($password, $server),
            default => null,
        };
    }

    /**
     * Build the rules for Clash.
     */
    public function buildRules($config)
    {
        // Force the current subscription domain to be a direct rule
        $subsDomain = request()->header('Host');
        if ($subsDomain) {
            array_unshift($config['rules'], "DOMAIN,{$subsDomain},DIRECT");
        }
        // // Force the nodes ip to be a direct rule
        // collect($this->servers)->pluck('host')->map(function ($host) {
        //     $host = trim($host);
        //     return filter_var($host, FILTER_VALIDATE_IP) ? [$host] : Helper::getIpByDomainName($host);
        // })->flatten()->unique()->each(function ($nodeIP) use (&$config) {
        //     array_unshift($config['rules'], "IP-CIDR,{$nodeIP}/32,DIRECT,no-resolve");
        // });

        return $config;
    }

    private function isMatch($exp, $str)
    {
        try {
            return preg_match($exp, $str) === 1;
        } catch (\Exception $e) {
            return false;
        }
    }

    private function isRegex($exp)
    {
        if (empty($exp)) {
            return false;
        }
        try {
            return preg_match($exp, '') !== false;
        } catch (\Exception $e) {
            return false;
        }
    }

}
