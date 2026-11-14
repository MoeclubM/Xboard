<?php

namespace App\Support;

use App\Utils\Helper;

class FluxConfig
{
    public const MAX_EXPANDED_PORTS = 64;
    public const IP_STRATEGIES = ['latency', 'dual', 'prefer_v4', 'prefer_v6', 'v4_only', 'v6_only'];
    public const SECURITY_MODES = ['obfs', 'tls'];
    public const TRANSPORTS = ['tcp', 'udp', 'http'];
    public const HTTP_MODES = ['ws', 'httpupgrade', 'h2'];
    public const CERT_MODES = ['inherit', 'file', 'origin_plain'];
    public const IP_VERSIONS = ['auto', 'ipv4', 'ipv6'];
    public const CHANNEL_ROLES = ['primary', 'udp_relay', 'prefer', 'backup'];

    public static function supportsClient(?\Illuminate\Http\Request $request, string $agent = '', ?string $clientName = null): bool
    {
        $types = strtolower(trim((string) $request?->query('types', '')));
        if ($types !== '' && $types !== 'all') {
            return in_array('flux', preg_split('/[|,\s]+/u', $types, -1, PREG_SPLIT_NO_EMPTY) ?: [], true);
        }
        $header = strtolower(trim((string) $request?->header('X-XBClient-Protocols', '')));
        if ($header !== '') {
            return in_array('flux', array_map('trim', explode(',', $header)), true);
        }
        return in_array(strtolower((string) $clientName), ['aerion', 'xbclient', 'neto'], true)
            || preg_match('/(?:^|[\s(;])(?:aerion|xbclient|neto)(?:[\/\s;)]|$)/i', $agent) === 1;
    }

    public static function parsePortSpec(mixed $spec, int $maxPorts = self::MAX_EXPANDED_PORTS): array
    {
        $raw = is_array($spec) ? implode(',', $spec) : trim((string) $spec);
        if ($raw === '' || $raw === '0') {
            return [];
        }
        $tokens = preg_split('/[,;\s]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $ports = [];
        $seen = [];
        foreach ($tokens as $token) {
            if (str_contains($token, '-')) {
                [$startRaw, $endRaw] = explode('-', $token, 2);
                if (!ctype_digit($startRaw) || !ctype_digit($endRaw)) {
                    throw new \InvalidArgumentException("端口段格式无效: {$token}");
                }
                $start = (int) $startRaw;
                $end = (int) $endRaw;
                if ($start < 1 || $end > 65535 || $start > $end) {
                    throw new \InvalidArgumentException("端口段范围无效: {$token}");
                }
                $span = $end - $start + 1;
                if (count($ports) + $span > $maxPorts) {
                    throw new \InvalidArgumentException("单节点展开端口总数不能超过 {$maxPorts}");
                }
                for ($port = $start; $port <= $end; $port++) {
                    if (!isset($seen[$port])) {
                        $seen[$port] = true;
                        $ports[] = $port;
                    }
                }
            } else {
                if (!ctype_digit($token)) {
                    throw new \InvalidArgumentException("端口格式无效: {$token}");
                }
                $port = (int) $token;
                if ($port < 1 || $port > 65535) {
                    throw new \InvalidArgumentException("端口超出范围: {$token}");
                }
                if (!isset($seen[$port])) {
                    if (count($ports) >= $maxPorts) {
                        throw new \InvalidArgumentException("单节点展开端口总数不能超过 {$maxPorts}");
                    }
                    $seen[$port] = true;
                    $ports[] = $port;
                }
            }
        }
        return $ports;
    }

    public static function generateObfsKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    public static function defaultChannels(string $obfsKey = ''): array
    {
        return [
            [
                'id' => 'tcp-v4',
                'enabled' => true,
                'connect_host' => '',
                'connect_ports' => '',
                'ip_version' => 'ipv4',
                'listen_ip' => '',
                'listen_ports' => '',
                'role' => 'primary',
                'weight' => 100,
                'transport' => 'tcp',
                'security' => 'obfs',
                'sni' => '',
                'allow_insecure' => null,
                'fingerprint' => '',
                'cert_mode' => 'inherit',
                'cert_path' => '',
                'key_path' => '',
                'obfs_key' => $obfsKey,
            ],
            [
                'id' => 'tcp-v6',
                'enabled' => true,
                'connect_host' => '',
                'connect_ports' => '',
                'ip_version' => 'ipv6',
                'listen_ip' => '',
                'listen_ports' => '',
                'role' => 'primary',
                'weight' => 100,
                'transport' => 'tcp',
                'security' => 'obfs',
                'sni' => '',
                'allow_insecure' => null,
                'fingerprint' => '',
                'cert_mode' => 'inherit',
                'cert_path' => '',
                'key_path' => '',
                'obfs_key' => $obfsKey,
            ],
        ];
    }

    public static function normalizeHeaders(mixed $headers): array
    {
        if (is_string($headers)) {
            $decoded = json_decode($headers, true);
            if (is_array($decoded)) {
                $headers = $decoded;
            } else {
                $parsed = [];
                foreach (preg_split('/\r?\n/', $headers) ?: [] as $line) {
                    $line = trim($line);
                    if ($line === '' || !str_contains($line, ':')) {
                        continue;
                    }
                    [$k, $v] = explode(':', $line, 2);
                    $k = trim($k);
                    if ($k !== '' && !ctype_digit($k)) {
                        $parsed[$k] = trim($v);
                    }
                }
                $headers = $parsed;
            }
        }
        if (!is_array($headers)) {
            return [];
        }
        $clean = [];
        foreach ($headers as $key => $value) {
            $name = trim((string) $key);
            if ($name === '' || ctype_digit($name) || is_array($value) || is_object($value)) {
                continue;
            }
            $clean[$name] = trim((string) $value);
        }
        return $clean;
    }

    public static function normalizeSettings(array $settings, bool $populateDefaults = false, bool $preserveInvalidEnums = false): array
    {
        $rawIpStrategy = strtolower(trim((string) ($settings['ip_strategy'] ?? '')));
        if ($rawIpStrategy === '') {
            $settings['ip_strategy'] = 'latency';
        } elseif (in_array($rawIpStrategy, self::IP_STRATEGIES, true)) {
            $settings['ip_strategy'] = $rawIpStrategy;
        } elseif ($preserveInvalidEnums) {
            $settings['ip_strategy'] = $rawIpStrategy;
        } else {
            $settings['ip_strategy'] = 'latency';
        }
        $settings['standby_channels'] = isset($settings['standby_channels']) ? (int) $settings['standby_channels'] : 2;
        $settings['rotation_interval_sec'] = isset($settings['rotation_interval_sec']) ? (int) $settings['rotation_interval_sec'] : 180;
        $settings['rotation_bytes_mb'] = isset($settings['rotation_bytes_mb']) ? (int) $settings['rotation_bytes_mb'] : 96;

        $legacyObfsKey = trim((string) ($settings['obfs_key'] ?? ''));
        unset($settings['security'], $settings['obfs_key'], $settings['reality_settings'], $settings['reality']);

        $rawChannels = is_array($settings['channels'] ?? null) ? array_values($settings['channels']) : [];
        if (empty($rawChannels) && $populateDefaults) {
            $seedKey = $legacyObfsKey !== '' ? $legacyObfsKey : self::generateObfsKey();
            $rawChannels = self::defaultChannels($seedKey);
        }

        $channels = [];
        foreach ($rawChannels as $idx => $ch) {
            if (!is_array($ch)) {
                continue;
            }
            $channels[] = self::normalizeChannel($ch, $idx, $legacyObfsKey, $preserveInvalidEnums);
        }

        if ($populateDefaults && !empty($channels)) {
            $obfsByBind = [];
            foreach ($channels as $ch) {
                if (empty($ch['enabled']) || ($ch['security'] ?? 'obfs') !== 'obfs' || ($ch['obfs_key'] ?? '') === '') {
                    continue;
                }
                $bindKey = self::channelBindKey($ch);
                if (!isset($obfsByBind[$bindKey])) {
                    $obfsByBind[$bindKey] = $ch['obfs_key'];
                }
            }
            foreach ($channels as &$ch) {
                if (($ch['security'] ?? 'obfs') !== 'obfs' || ($ch['obfs_key'] ?? '') !== '') {
                    continue;
                }
                $bindKey = self::channelBindKey($ch);
                if (isset($obfsByBind[$bindKey])) {
                    $ch['obfs_key'] = $obfsByBind[$bindKey];
                } else {
                    $generated = self::generateObfsKey();
                    $ch['obfs_key'] = $generated;
                    if (!empty($ch['enabled'])) {
                        $obfsByBind[$bindKey] = $generated;
                    }
                }
            }
            unset($ch);
        }

        $settings['channels'] = $channels;

        return $settings;
    }

    private static function channelBindKey(array $ch): string
    {
        $ip = ($ch['listen_ip'] ?? '') !== '' ? $ch['listen_ip'] : '0.0.0.0';
        $ports = ($ch['listen_ports'] ?? '') !== '' ? $ch['listen_ports'] : ($ch['connect_ports'] ?? '');
        $proto = ($ch['transport'] ?? 'tcp') === 'udp' ? 'udp' : 'tcp';
        return "{$ip}:{$ports}/{$proto}";
    }

    private static function normalizeChannel(array $ch, int $index, string $legacyObfsKey, bool $preserveInvalidEnums = false): array
    {
        $id = trim((string) ($ch['id'] ?? ''));
        if ($id === '') {
            $id = 'ch-' . ($index + 1);
        }
        $enabled = array_key_exists('enabled', $ch) ? (bool) $ch['enabled'] : true;
        $rawTransport = strtolower(trim((string) ($ch['transport'] ?? '')));
        if ($rawTransport === '') {
            $transport = 'tcp';
        } elseif (in_array($rawTransport, self::TRANSPORTS, true)) {
            $transport = $rawTransport;
        } else {
            $transport = $preserveInvalidEnums ? $rawTransport : 'tcp';
        }
        $rawIpVersion = strtolower(trim((string) ($ch['ip_version'] ?? '')));
        if ($rawIpVersion === '') {
            $ipVersion = 'auto';
        } elseif (in_array($rawIpVersion, self::IP_VERSIONS, true)) {
            $ipVersion = $rawIpVersion;
        } else {
            $ipVersion = $preserveInvalidEnums ? $rawIpVersion : 'auto';
        }
        $rawRole = strtolower(trim((string) ($ch['role'] ?? '')));
        if ($rawRole === '') {
            $role = 'primary';
        } elseif (in_array($rawRole, self::CHANNEL_ROLES, true)) {
            $role = ($rawRole === 'udp_relay' && $transport !== 'udp') ? 'primary' : $rawRole;
        } else {
            $role = $preserveInvalidEnums ? $rawRole : 'primary';
        }
        $weight = isset($ch['weight']) ? (int) $ch['weight'] : 100;

        $chSec = strtolower(trim((string) ($ch['security'] ?? '')));
        if ($chSec === '') {
            $chSec = 'obfs';
        } elseif (!in_array($chSec, self::SECURITY_MODES, true) && !$preserveInvalidEnums) {
            $chSec = 'obfs';
        }

        $httpMode = strtolower(trim((string) ($ch['http_mode'] ?? '')));
        if (!in_array($httpMode, self::HTTP_MODES, true)) {
            $httpMode = $transport === 'http' ? 'ws' : '';
        }

        $certMode = strtolower(trim((string) ($ch['cert_mode'] ?? 'inherit')));
        if (!in_array($certMode, self::CERT_MODES, true)) {
            $certMode = 'inherit';
        }

        $obfsKey = trim((string) ($ch['obfs_key'] ?? ''));
        if ($chSec === 'obfs' && $obfsKey === '' && $legacyObfsKey !== '') {
            $obfsKey = $legacyObfsKey;
        }

        $normalized = [
            'id' => $id,
            'enabled' => $enabled,
            'connect_host' => trim((string) ($ch['connect_host'] ?? '')),
            'connect_ports' => trim((string) ($ch['connect_ports'] ?? '')),
            'ip_version' => $ipVersion,
            'listen_ip' => trim((string) ($ch['listen_ip'] ?? '')),
            'listen_ports' => trim((string) ($ch['listen_ports'] ?? '')),
            'role' => $role,
            'weight' => $weight,
            'transport' => $transport,
            'security' => $chSec,
            'sni' => trim((string) ($ch['sni'] ?? '')),
            'allow_insecure' => isset($ch['allow_insecure']) ? (bool) $ch['allow_insecure'] : null,
            'fingerprint' => trim((string) ($ch['fingerprint'] ?? '')),
            'cert_mode' => $certMode,
            'cert_path' => trim((string) ($ch['cert_path'] ?? '')),
            'key_path' => trim((string) ($ch['key_path'] ?? '')),
            'obfs_key' => $obfsKey,
        ];
        if ($transport === 'http') {
            $normalized['http_mode'] = $httpMode !== '' ? $httpMode : 'ws';
            $normalized['http_host'] = trim((string) ($ch['http_host'] ?? ''));
            $normalized['http_path'] = trim((string) ($ch['http_path'] ?? '/')) ?: '/';
            $headers = self::normalizeHeaders($ch['http_headers'] ?? []);
            if (!empty($headers)) {
                $normalized['http_headers'] = $headers;
            }
        }

        return $normalized;
    }

    public static function validateSettings(array $settings, mixed $nodePort, mixed $serverPort, callable $fail): void
    {
        $channels = $settings['channels'] ?? [];
        if (empty($channels)) {
            try {
                $defaultPorts = self::parsePortSpec($nodePort);
                if (empty($defaultPorts)) {
                    $fail('port', '连接端口不能为空');
                }
                if (count($defaultPorts) * 2 > self::MAX_EXPANDED_PORTS) {
                    $fail('port', '默认双通道展开后的端口总数不能超过 ' . self::MAX_EXPANDED_PORTS);
                }
            } catch (\InvalidArgumentException $e) {
                $fail('port', $e->getMessage());
            }
            if ((int) $serverPort <= 0) {
                $fail('server_port', '未配置手动通道时后端服务端口必须大于 0');
            }
            return;
        }

        $enabledChannels = array_values(array_filter($channels, fn($ch) => !empty($ch['enabled'])));
        if (empty($enabledChannels)) {
            $fail('protocol_settings.channels', 'Flux 节点至少需要保留一条启用的通道');
            return;
        }

        $totalClientPorts = 0;
        $serverPortBindings = [];
        foreach ($channels as $idx => $ch) {
            if (empty($ch['enabled'])) {
                continue;
            }
            $prefix = "protocol_settings.channels.{$idx}";
            $weight = (int) ($ch['weight'] ?? 100);
            if ($weight < 1 || $weight > 100) {
                $fail("{$prefix}.weight", '通道权重必须在 1 到 100 之间');
            }

            try {
                $cPorts = self::parsePortSpec($ch['connect_ports'] ?? '', self::MAX_EXPANDED_PORTS);
                if (empty($cPorts)) {
                    $cPorts = self::parsePortSpec($nodePort, self::MAX_EXPANDED_PORTS);
                }
                if (empty($cPorts)) {
                    $fail("{$prefix}.connect_ports", '通道连接端口不能为空');
                }
                $totalClientPorts += count($cPorts);
                if ($totalClientPorts > self::MAX_EXPANDED_PORTS) {
                    $fail("{$prefix}.connect_ports", '所有启用通道展开后的连接端口总数不能超过 ' . self::MAX_EXPANDED_PORTS);
                }
            } catch (\InvalidArgumentException $e) {
                $fail("{$prefix}.connect_ports", $e->getMessage());
            }

            try {
                $lPorts = self::parsePortSpec($ch['listen_ports'] ?? '', self::MAX_EXPANDED_PORTS);
                if (empty($lPorts)) {
                    $lPorts = self::parsePortSpec($ch['connect_ports'] ?? '', self::MAX_EXPANDED_PORTS);
                }
                if (empty($lPorts)) {
                    if ((int) $serverPort <= 0) {
                        $fail("{$prefix}.listen_ports", '通道监听端口不能为空');
                    } else {
                        $lPorts = [(int) $serverPort];
                    }
                }
                $listenIp = ($ch['listen_ip'] ?? '') !== '' ? $ch['listen_ip'] : '0.0.0.0';
                $protoKey = ($ch['transport'] ?? 'tcp') === 'udp' ? 'udp' : 'tcp';
                $transport = $ch['transport'] ?? 'tcp';
                $sec = ($ch['security'] ?? '') !== '' ? $ch['security'] : 'obfs';
                $sig = implode('|', [
                    $transport,
                    $transport === 'http' ? ($ch['http_mode'] ?? 'ws') : '',
                    $transport === 'http' ? ($ch['http_host'] ?? '') : '',
                    $transport === 'http' ? ($ch['http_path'] ?? '/') : '',
                    $sec,
                    $sec === 'obfs' ? ($ch['obfs_key'] ?? '') : (($ch['cert_mode'] ?? 'inherit') . ':' . ($ch['cert_path'] ?? '') . ':' . ($ch['key_path'] ?? '')),
                ]);
                foreach ($lPorts as $lp) {
                    $bindKey = "{$listenIp}:{$lp}/{$protoKey}";
                    if (isset($serverPortBindings[$bindKey]) && $serverPortBindings[$bindKey] !== $sig) {
                        $fail("{$prefix}.listen_ports", "本地监听端口 {$listenIp}:{$lp} 与其他通道的传输或安全配置冲突");
                        break;
                    }
                    $serverPortBindings[$bindKey] = $sig;
                }
                if (count($serverPortBindings) > self::MAX_EXPANDED_PORTS) {
                    $fail("{$prefix}.listen_ports", '单节点展开后的总监听端口数不能超过 ' . self::MAX_EXPANDED_PORTS);
                }
            } catch (\InvalidArgumentException $e) {
                $fail("{$prefix}.listen_ports", $e->getMessage());
            }

            $transport = $ch['transport'] ?? 'tcp';
            $sec = ($ch['security'] ?? '') !== '' ? $ch['security'] : 'obfs';
            $certMode = $ch['cert_mode'] ?? 'inherit';

            if ($sec === 'tls') {
                if ($transport === 'udp' && $certMode === 'origin_plain') {
                    $fail("{$prefix}.cert_mode", 'UDP 通道不支持 origin_plain 明文回源模式');
                }
                if ($certMode === 'file') {
                    if (trim((string) ($ch['cert_path'] ?? '')) === '') {
                        $fail("{$prefix}.cert_path", '独立文件证书模式必须填写证书文件路径');
                    }
                    if (trim((string) ($ch['key_path'] ?? '')) === '') {
                        $fail("{$prefix}.key_path", '独立文件证书模式必须填写私钥文件路径');
                    }
                }
            } elseif ($sec === 'obfs') {
                $effObfs = trim((string) ($ch['obfs_key'] ?? ''));
                if (strlen($effObfs) < 4) {
                    $fail("{$prefix}.obfs_key", '启用混淆的通道必须配置至少 4 字符的混淆密钥');
                }
            }
        }
    }

    public static function toNodeServerPayload(array $settings): array
    {
        $normalized = self::normalizeSettings($settings);
        $payload = [
            'ip_strategy' => $normalized['ip_strategy'],
            'standby_channels' => (int) $normalized['standby_channels'],
            'rotation_interval_sec' => (int) $normalized['rotation_interval_sec'],
            'rotation_bytes_mb' => (int) $normalized['rotation_bytes_mb'],
        ];

        $channels = [];
        foreach ($normalized['channels'] as $ch) {
            $sec = ($ch['security'] ?? '') === 'tls' ? 'tls' : 'obfs';
            $item = [
                'id' => $ch['id'],
                'enabled' => (bool) $ch['enabled'],
                'connect_host' => $ch['connect_host'] ?? '',
                'connect_ports' => $ch['connect_ports'] ?? '',
                'ip_version' => $ch['ip_version'] ?? 'auto',
                'listen_ip' => $ch['listen_ip'] ?? '',
                'listen_ports' => $ch['listen_ports'] ?? '',
                'role' => $ch['role'] ?? 'primary',
                'weight' => (int) ($ch['weight'] ?? 100),
                'transport' => $ch['transport'] ?? 'tcp',
                'security' => $sec,
                'cert_mode' => $ch['cert_mode'] ?? 'inherit',
            ];
            if ($sec === 'tls' && !empty($ch['sni'])) {
                $item['sni'] = $ch['sni'];
            }
            if (($ch['transport'] ?? 'tcp') === 'http') {
                $item['http_mode'] = $ch['http_mode'] ?? 'ws';
                if (!empty($ch['http_host'])) {
                    $item['http_host'] = $ch['http_host'];
                }
                $item['http_path'] = $ch['http_path'] ?? '/';
                $headers = self::normalizeHeaders($ch['http_headers'] ?? []);
                if (!empty($headers)) {
                    $item['http_headers'] = $headers;
                }
            }
            if ($sec === 'tls' && ($ch['cert_mode'] ?? 'inherit') === 'file') {
                if (!empty($ch['cert_path'])) {
                    $item['cert_path'] = $ch['cert_path'];
                }
                if (!empty($ch['key_path'])) {
                    $item['key_path'] = $ch['key_path'];
                }
            }
            if ($sec === 'obfs' && !empty($ch['obfs_key'])) {
                $item['obfs_key'] = $ch['obfs_key'];
            }
            $channels[] = $item;
        }
        $payload['channels'] = $channels;

        return $payload;
    }

    public static function toClientProxy(string $password, array $server): array
    {
        $rawSettings = is_array($server['protocol_settings'] ?? null) ? $server['protocol_settings'] : [];
        $legacyObfsKey = trim((string) ($rawSettings['obfs_key'] ?? ''));
        $settings = self::normalizeSettings($rawSettings);
        $nodeTls = is_array($settings['tls_settings'] ?? null) ? $settings['tls_settings'] : [];

        $proxy = [
            'name' => $server['name'],
            'type' => 'flux',
            'server' => $server['host'],
            'port' => (int) $server['port'],
            'key' => $password,
            'udp' => true,
            'ip-strategy' => $settings['ip_strategy'],
            'standby-channels' => (int) $settings['standby_channels'],
            'rotation-interval-sec' => (int) $settings['rotation_interval_sec'],
            'rotation-bytes-mb' => (int) $settings['rotation_bytes_mb'],
        ];

        $sni = self::firstNonEmpty([$nodeTls['server_name'] ?? '']);
        if ($sni !== null) {
            $proxy['servername'] = $sni;
        }

        if (!empty($nodeTls['allow_insecure'])) {
            $proxy['skip-cert-verify'] = true;
        }

        $fp = Helper::getTlsFingerprint($settings['utls'] ?? null);
        if ($fp) {
            $proxy['client-fingerprint'] = $fp;
        }

        $clientChannels = [];
        foreach ($settings['channels'] as $ch) {
            if (empty($ch['enabled'])) {
                continue;
            }
            $chSec = ($ch['security'] ?? '') === 'tls' ? 'tls' : 'obfs';
            $item = [
                'id' => $ch['id'],
                'enabled' => true,
                'ip-version' => $ch['ip_version'] ?? 'auto',
                'role' => $ch['role'] ?? 'primary',
                'weight' => (int) ($ch['weight'] ?? 100),
                'transport' => $ch['transport'] ?? 'tcp',
                'security' => $chSec,
            ];
            if (!empty($ch['connect_host'])) {
                $item['server'] = $ch['connect_host'];
            }
            if (!empty($ch['connect_ports']) && $ch['connect_ports'] !== '0') {
                $item['ports'] = $ch['connect_ports'];
            } elseif (!empty($server['ports'])) {
                $item['ports'] = (string) $server['ports'];
            }
            if (($ch['transport'] ?? 'tcp') === 'http') {
                $item['http-mode'] = $ch['http_mode'] ?? 'ws';
                if (!empty($ch['http_host'])) {
                    $item['http-host'] = $ch['http_host'];
                }
                $item['http-path'] = $ch['http_path'] ?? '/';
                $headers = self::normalizeHeaders($ch['http_headers'] ?? []);
                if (!empty($headers)) {
                    $item['http-headers'] = $headers;
                }
            }
            if ($chSec === 'tls') {
                $chSni = self::firstNonEmpty([$ch['sni'] ?? '']);
                if ($chSni !== null) {
                    $item['sni'] = $chSni;
                }
                if ($ch['allow_insecure'] !== null) {
                    $item['skip-cert-verify'] = (bool) $ch['allow_insecure'];
                }
                if (!empty($ch['fingerprint'])) {
                    $item['client-fingerprint'] = $ch['fingerprint'];
                }
            } else {
                $chObfs = !empty($ch['obfs_key']) ? $ch['obfs_key'] : $legacyObfsKey;
                if ($chObfs !== '') {
                    $item['obfs-key'] = $chObfs;
                }
            }
            $clientChannels[] = $item;
        }

        if (!empty($clientChannels)) {
            $proxy['channels'] = $clientChannels;
        } else {
            $fallbackPorts = (string) (($server['ports'] ?? '') !== '' ? $server['ports'] : ($server['port'] ?? ''));
            if ($fallbackPorts !== '' && $fallbackPorts !== '0') {
                $baseChannel = [
                    'enabled' => true,
                    'ports' => $fallbackPorts,
                    'transport' => 'tcp',
                    'security' => 'obfs',
                    'role' => 'primary',
                    'weight' => 100,
                ];
                if ($legacyObfsKey !== '') {
                    $baseChannel['obfs-key'] = $legacyObfsKey;
                }
                $proxy['channels'] = [
                    ['id' => 'tcp-v4', 'ip-version' => 'ipv4', ...$baseChannel],
                    ['id' => 'tcp-v6', 'ip-version' => 'ipv6', ...$baseChannel],
                ];
            }
        }

        return $proxy;
    }

    private static function firstNonEmpty(array $candidates): ?string
    {
        foreach ($candidates as $candidate) {
            $trimmed = trim((string) $candidate);
            if ($trimmed !== '') {
                return $trimmed;
            }
        }
        return null;
    }
}
