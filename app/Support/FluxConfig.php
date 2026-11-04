<?php

namespace App\Support;

use App\Utils\Helper;

class FluxConfig
{
    public const MAX_EXPANDED_PORTS = 64;
    public const IP_STRATEGIES = ['dual', 'prefer_v4', 'prefer_v6', 'v4_only', 'v6_only'];
    public const SECURITY_MODES = ['reality', 'tls', 'obfs'];
    public const TRANSPORTS = ['tcp', 'udp', 'http'];
    public const HTTP_MODES = ['ws', 'httpupgrade', 'h2'];
    public const CERT_MODES = ['inherit', 'file', 'origin_plain'];
    public const IP_VERSIONS = ['auto', 'ipv4', 'ipv6'];
    public const CHANNEL_ROLES = ['primary', 'backup'];

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
        return in_array(strtolower((string) $clientName), ['aerion', 'xbclient'], true)
            || preg_match('/(?:^|[\s(;])(?:aerion|xbclient)(?:[\/\s;)]|$)/i', $agent) === 1;
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

    public static function decodeRealityKey(?string $encoded): ?string
    {
        $trimmed = trim((string) $encoded);
        if ($trimmed === '') {
            return null;
        }
        $normalized = strtr($trimmed, '-_', '+/');
        $pad = strlen($normalized) % 4;
        if ($pad > 0) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if ($decoded === false || strlen($decoded) !== 32) {
            return null;
        }
        return $decoded;
    }

    public static function deriveRealityPublicKey(?string $privateKey): ?string
    {
        $rawPrivate = self::decodeRealityKey($privateKey);
        if ($rawPrivate === null || !function_exists('sodium_crypto_scalarmult_base')) {
            return null;
        }
        $rawPublic = sodium_crypto_scalarmult_base($rawPrivate);
        return rtrim(strtr(base64_encode($rawPublic), '+/', '-_'), '=');
    }

    public static function generateObfsKey(): string
    {
        return bin2hex(random_bytes(16));
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

    public static function normalizeSettings(array $settings): array
    {
        $security = strtolower(trim((string) ($settings['security'] ?? 'reality')));
        if (!in_array($security, self::SECURITY_MODES, true)) {
            $security = 'reality';
        }
        $settings['security'] = $security;

        $ipStrategy = strtolower(trim((string) ($settings['ip_strategy'] ?? 'dual')));
        $settings['ip_strategy'] = in_array($ipStrategy, self::IP_STRATEGIES, true) ? $ipStrategy : 'dual';
        $settings['standby_channels'] = isset($settings['standby_channels']) ? (int) $settings['standby_channels'] : 2;
        $settings['rotation_interval_sec'] = isset($settings['rotation_interval_sec']) ? (int) $settings['rotation_interval_sec'] : 180;
        $settings['rotation_bytes_mb'] = isset($settings['rotation_bytes_mb']) ? (int) $settings['rotation_bytes_mb'] : 96;

        $obfsKey = trim((string) ($settings['obfs_key'] ?? ''));
        if ($security === 'obfs' && $obfsKey === '') {
            $obfsKey = self::generateObfsKey();
        }
        $settings['obfs_key'] = $obfsKey;

        $reality = is_array($settings['reality_settings'] ?? null)
            ? $settings['reality_settings']
            : (is_array($settings['reality'] ?? null) ? $settings['reality'] : []);
        $settings['reality_settings'] = self::normalizeRealityBlock($reality);

        $rawChannels = is_array($settings['channels'] ?? null) ? array_values($settings['channels']) : [];
        $channels = [];
        foreach ($rawChannels as $idx => $ch) {
            if (!is_array($ch)) {
                continue;
            }
            $channels[] = self::normalizeChannel($ch, $idx, $security, $settings['obfs_key']);
        }
        $settings['channels'] = $channels;
        unset($settings['reality']);

        return $settings;
    }

    private static function normalizeRealityBlock(array $reality): array
    {
        $priv = trim((string) ($reality['private_key'] ?? ''));
        $pub = trim((string) ($reality['public_key'] ?? ''));
        if ($priv !== '' && $pub === '') {
            $pub = self::deriveRealityPublicKey($priv) ?? '';
        }
        $port = isset($reality['server_port']) && (int) $reality['server_port'] > 0
            ? (int) $reality['server_port']
            : 443;
        $out = [
            'server_name' => trim((string) ($reality['server_name'] ?? '')),
            'server_port' => $port,
            'public_key' => $pub,
            'private_key' => $priv,
            'short_id' => strtolower(trim((string) ($reality['short_id'] ?? ''))),
            'dest' => trim((string) ($reality['dest'] ?? '')),
            'allow_insecure' => (bool) ($reality['allow_insecure'] ?? false),
        ];
        if (array_key_exists('fallback', $reality) && $reality['fallback'] !== null && $reality['fallback'] !== '') {
            $out['fallback'] = (bool) $reality['fallback'];
        }
        return $out;
    }

    private static function normalizeChannel(array $ch, int $index, string $defaultSecurity, string $defaultObfsKey): array
    {
        $id = trim((string) ($ch['id'] ?? ''));
        if ($id === '') {
            $id = 'ch-' . ($index + 1);
        }
        $enabled = array_key_exists('enabled', $ch) ? (bool) $ch['enabled'] : true;
        $transport = strtolower(trim((string) ($ch['transport'] ?? 'tcp')));
        if (!in_array($transport, self::TRANSPORTS, true)) {
            $transport = 'tcp';
        }
        $ipVersion = strtolower(trim((string) ($ch['ip_version'] ?? 'auto')));
        if (!in_array($ipVersion, self::IP_VERSIONS, true)) {
            $ipVersion = 'auto';
        }
        $role = strtolower(trim((string) ($ch['role'] ?? 'primary')));
        if (!in_array($role, self::CHANNEL_ROLES, true)) {
            $role = 'primary';
        }
        $weight = isset($ch['weight']) ? (int) $ch['weight'] : 100;

        $chSec = strtolower(trim((string) ($ch['security'] ?? '')));
        if (!in_array($chSec, self::SECURITY_MODES, true)) {
            $chSec = '';
        }
        $effectiveSec = $chSec !== '' ? $chSec : $defaultSecurity;

        $httpMode = strtolower(trim((string) ($ch['http_mode'] ?? '')));
        if (!in_array($httpMode, self::HTTP_MODES, true)) {
            $httpMode = $transport === 'http' ? 'ws' : '';
        }

        $certMode = strtolower(trim((string) ($ch['cert_mode'] ?? 'inherit')));
        if (!in_array($certMode, self::CERT_MODES, true)) {
            $certMode = 'inherit';
        }

        $obfsKey = trim((string) ($ch['obfs_key'] ?? ''));
        if ($effectiveSec === 'obfs' && $obfsKey === '' && $defaultObfsKey === '') {
            $obfsKey = self::generateObfsKey();
        }

        $chRealityRaw = is_array($ch['reality'] ?? null)
            ? $ch['reality']
            : (is_array($ch['reality_settings'] ?? null) ? $ch['reality_settings'] : []);
        $chReality = self::normalizeRealityBlock($chRealityRaw);

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
            'sni' => trim((string) ($ch['sni'] ?? '')),
            'allow_insecure' => isset($ch['allow_insecure']) ? (bool) $ch['allow_insecure'] : null,
            'fingerprint' => trim((string) ($ch['fingerprint'] ?? '')),
            'cert_mode' => $certMode,
            'cert_path' => trim((string) ($ch['cert_path'] ?? '')),
            'key_path' => trim((string) ($ch['key_path'] ?? '')),
            'obfs_key' => $obfsKey,
        ];
        if ($chSec !== '') {
            $normalized['security'] = $chSec;
        }
        if ($transport === 'http') {
            $normalized['http_mode'] = $httpMode !== '' ? $httpMode : 'ws';
            $normalized['http_host'] = trim((string) ($ch['http_host'] ?? ''));
            $normalized['http_path'] = trim((string) ($ch['http_path'] ?? '/')) ?: '/';
            $headers = self::normalizeHeaders($ch['http_headers'] ?? []);
            if (!empty($headers)) {
                $normalized['http_headers'] = $headers;
            }
        }
        if (
            $chReality['private_key'] !== ''
            || $chReality['public_key'] !== ''
            || $chReality['server_name'] !== ''
            || $chReality['dest'] !== ''
            || $chReality['short_id'] !== ''
        ) {
            $normalized['reality'] = $chReality;
        }

        return $normalized;
    }

    public static function validateSettings(array $settings, mixed $nodePort, mixed $serverPort, callable $fail): void
    {
        $defaultSec = $settings['security'] ?? 'reality';
        $nodeReality = $settings['reality_settings'] ?? [];
        $nodeObfsKey = trim((string) ($settings['obfs_key'] ?? ''));

        if ($nodeReality['short_id'] ?? '') {
            if (!preg_match('/^(?:[0-9a-fA-F]{2}){0,8}$/', (string) $nodeReality['short_id'])) {
                $fail('protocol_settings.reality_settings.short_id', 'REALITY short_id 必须是不超过 16 位的偶数长度十六进制字符串');
            }
        }
        if (($nodeReality['private_key'] ?? '') !== '' && self::decodeRealityKey($nodeReality['private_key']) === null) {
            $fail('protocol_settings.reality_settings.private_key', 'REALITY 私钥格式无效，需为 32 字节 Base64 密钥');
        }
        if (($nodeReality['public_key'] ?? '') !== '' && self::decodeRealityKey($nodeReality['public_key']) === null) {
            $fail('protocol_settings.reality_settings.public_key', 'REALITY 公钥格式无效，需为 32 字节 Base64 密钥');
        }

        $channels = $settings['channels'] ?? [];
        if (empty($channels)) {
            try {
                $defaultPorts = self::parsePortSpec($nodePort);
                if (count($defaultPorts) * 2 > self::MAX_EXPANDED_PORTS) {
                    $fail('port', '默认双通道展开后的端口总数不能超过 ' . self::MAX_EXPANDED_PORTS);
                }
            } catch (\InvalidArgumentException $e) {
                $fail('port', $e->getMessage());
            }
            if ((int) $serverPort <= 0) {
                $fail('server_port', '未配置手动通道时后端服务端口必须大于 0');
            }
            if ($defaultSec === 'reality') {
                if (self::decodeRealityKey($nodeReality['private_key'] ?? '') === null) {
                    $fail('protocol_settings.reality_settings.private_key', '启用 REALITY 时必须填写有效的服务端私钥');
                }
                if (trim((string) ($nodeReality['server_name'] ?? '')) === '' && trim((string) ($nodeReality['dest'] ?? '')) === '') {
                    $fail('protocol_settings.reality_settings.server_name', '启用 REALITY 时必须填写目标域名 SNI 或回源地址');
                }
            } elseif ($defaultSec === 'obfs' && strlen($nodeObfsKey) < 4) {
                $fail('protocol_settings.obfs_key', '混淆密钥长度至少为 4 个字符');
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
                foreach ($lPorts as $lp) {
                    $serverPortBindings["{$listenIp}:{$lp}/{$protoKey}"] = true;
                }
                if (count($serverPortBindings) > self::MAX_EXPANDED_PORTS) {
                    $fail("{$prefix}.listen_ports", '单节点展开后的总监听端口数不能超过 ' . self::MAX_EXPANDED_PORTS);
                }
            } catch (\InvalidArgumentException $e) {
                $fail("{$prefix}.listen_ports", $e->getMessage());
            }

            $transport = $ch['transport'] ?? 'tcp';
            $sec = ($ch['security'] ?? '') !== '' ? $ch['security'] : $defaultSec;
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
            } elseif ($sec === 'reality') {
                $chR = $ch['reality'] ?? [];
                $priv = ($chR['private_key'] ?? '') !== '' ? $chR['private_key'] : ($nodeReality['private_key'] ?? '');
                if (self::decodeRealityKey($priv) === null) {
                    $fail("{$prefix}.reality.private_key", '启用 REALITY 的通道必须配置有效的 32 字节私钥');
                }
                $sni = self::firstNonEmpty([
                    $ch['sni'] ?? '',
                    $chR['server_name'] ?? '',
                    $chR['dest'] ?? '',
                    $nodeReality['server_name'] ?? '',
                    $nodeReality['dest'] ?? '',
                ]);
                if ($sni === null) {
                    $fail("{$prefix}.sni", '启用 REALITY 的通道必须配置借用域名 SNI 或回源地址');
                }
                $sid = $chR['short_id'] ?? '';
                if ($sid !== '' && !preg_match('/^(?:[0-9a-fA-F]{2}){0,8}$/', (string) $sid)) {
                    $fail("{$prefix}.reality.short_id", '通道 REALITY short_id 格式无效');
                }
            } elseif ($sec === 'obfs') {
                $effObfs = ($ch['obfs_key'] ?? '') !== '' ? $ch['obfs_key'] : $nodeObfsKey;
                if (strlen($effObfs) < 4) {
                    $fail("{$prefix}.obfs_key", '启用混淆的通道必须配置至少 4 字符的混淆密钥');
                }
            }
        }
    }

    public static function toNodeServerPayload(array $settings): array
    {
        $normalized = self::normalizeSettings($settings);
        $reality = $normalized['reality_settings'] ?? [];
        $payload = [
            'ip_strategy' => $normalized['ip_strategy'],
            'standby_channels' => (int) $normalized['standby_channels'],
            'rotation_interval_sec' => (int) $normalized['rotation_interval_sec'],
            'rotation_bytes_mb' => (int) $normalized['rotation_bytes_mb'],
            'security' => $normalized['security'],
        ];
        if (($normalized['obfs_key'] ?? '') !== '') {
            $payload['obfs_key'] = $normalized['obfs_key'];
        }
        if (!empty(array_filter($reality, fn($v) => $v !== null && $v !== '' && $v !== false))) {
            $payload['reality'] = self::cleanRealityForServer($reality);
        }

        $channels = [];
        foreach ($normalized['channels'] as $ch) {
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
                'cert_mode' => $ch['cert_mode'] ?? 'inherit',
            ];
            if (!empty($ch['security'])) {
                $item['security'] = $ch['security'];
            }
            if (!empty($ch['sni'])) {
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
            if (($ch['cert_mode'] ?? 'inherit') === 'file') {
                if (!empty($ch['cert_path'])) {
                    $item['cert_path'] = $ch['cert_path'];
                }
                if (!empty($ch['key_path'])) {
                    $item['key_path'] = $ch['key_path'];
                }
            }
            if (!empty($ch['obfs_key'])) {
                $item['obfs_key'] = $ch['obfs_key'];
            }
            if (!empty($ch['reality']) && is_array($ch['reality'])) {
                $cleanR = self::cleanRealityForServer($ch['reality']);
                if (!empty($cleanR)) {
                    $item['reality'] = $cleanR;
                }
            }
            $channels[] = $item;
        }
        $payload['channels'] = $channels;

        return $payload;
    }

    private static function cleanRealityForServer(array $reality): array
    {
        $out = [];
        foreach (['dest', 'server_name', 'private_key', 'short_id'] as $key) {
            $val = trim((string) ($reality[$key] ?? ''));
            if ($val !== '') {
                $out[$key] = $val;
            }
        }
        if (!empty($reality['server_port']) && (int) $reality['server_port'] > 0) {
            $out['server_port'] = (int) $reality['server_port'];
        }
        if (array_key_exists('fallback', $reality) && $reality['fallback'] !== null && $reality['fallback'] !== '') {
            $out['fallback'] = (bool) $reality['fallback'];
        }
        return $out;
    }

    public static function toClashClientProxy(string $password, array $server): array
    {
        $rawSettings = is_array($server['protocol_settings'] ?? null) ? $server['protocol_settings'] : [];
        $settings = self::normalizeSettings($rawSettings);
        $security = $settings['security'];
        $nodeReality = $settings['reality_settings'] ?? [];
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
            'security' => $security,
        ];

        $sni = $security === 'reality'
            ? self::firstNonEmpty([$nodeReality['server_name'] ?? '', self::extractDestHost($nodeReality['dest'] ?? '')])
            : self::firstNonEmpty([$nodeTls['server_name'] ?? '']);
        if ($sni !== null) {
            $proxy['servername'] = $sni;
        }

        $insecure = $security === 'reality'
            ? (bool) ($nodeReality['allow_insecure'] ?? false)
            : (bool) ($nodeTls['allow_insecure'] ?? false);
        if ($insecure) {
            $proxy['skip-cert-verify'] = true;
        }

        $fp = Helper::getTlsFingerprint($settings['utls'] ?? null);
        if ($fp) {
            $proxy['client-fingerprint'] = $fp;
        } elseif ($security === 'reality') {
            $proxy['client-fingerprint'] = 'chrome';
        }

        if ($security === 'reality') {
            $pubKey = trim((string) ($nodeReality['public_key'] ?? ''));
            if ($pubKey === '' && !empty($nodeReality['private_key'])) {
                $pubKey = self::deriveRealityPublicKey($nodeReality['private_key']) ?? '';
            }
            if ($pubKey !== '') {
                $proxy['reality-opts'] = [
                    'public-key' => $pubKey,
                    'short-id' => strtolower(trim((string) ($nodeReality['short_id'] ?? ''))),
                ];
            }
        } elseif ($security === 'obfs' && ($settings['obfs_key'] ?? '') !== '') {
            $proxy['obfs-key'] = $settings['obfs_key'];
        }

        $clientChannels = [];
        foreach ($settings['channels'] as $ch) {
            if (empty($ch['enabled'])) {
                continue;
            }
            $chSec = !empty($ch['security']) ? $ch['security'] : $security;
            $item = [
                'id' => $ch['id'],
                'enabled' => true,
                'ip-version' => $ch['ip_version'] ?? 'auto',
                'role' => $ch['role'] ?? 'primary',
                'weight' => (int) ($ch['weight'] ?? 100),
                'transport' => $ch['transport'] ?? 'tcp',
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
            if (!empty($ch['security'])) {
                $item['security'] = $ch['security'];
            }
            $chR = is_array($ch['reality'] ?? null) ? $ch['reality'] : [];
            $chSni = self::firstNonEmpty([
                $ch['sni'] ?? '',
                $chSec === 'reality' ? ($chR['server_name'] ?? '') : '',
                $chSec === 'reality' ? self::extractDestHost($chR['dest'] ?? '') : '',
            ]);
            if ($chSni !== null) {
                $item['sni'] = $chSni;
            }
            if ($ch['allow_insecure'] !== null) {
                $item['skip-cert-verify'] = $ch['allow_insecure'];
            }
            if (!empty($ch['fingerprint'])) {
                $item['client-fingerprint'] = $ch['fingerprint'];
            }
            if ($chSec === 'reality') {
                $chPub = trim((string) ($chR['public_key'] ?? ''));
                if ($chPub === '' && !empty($chR['private_key'])) {
                    $chPub = self::deriveRealityPublicKey($chR['private_key']) ?? '';
                }
                $chSid = strtolower(trim((string) ($chR['short_id'] ?? '')));
                if ($chPub !== '') {
                    $item['reality-opts'] = [
                        'public-key' => $chPub,
                        'short-id' => $chSid !== '' ? $chSid : strtolower(trim((string) ($nodeReality['short_id'] ?? ''))),
                    ];
                } else {
                    $fallbackPub = trim((string) ($nodeReality['public_key'] ?? ''));
                    if ($fallbackPub === '' && !empty($nodeReality['private_key'])) {
                        $fallbackPub = self::deriveRealityPublicKey($nodeReality['private_key']) ?? '';
                    }
                    if ($fallbackPub !== '') {
                        $item['reality-opts'] = [
                            'public-key' => $fallbackPub,
                            'short-id' => $chSid !== '' ? $chSid : strtolower(trim((string) ($nodeReality['short_id'] ?? ''))),
                        ];
                    }
                }
            } elseif ($chSec === 'obfs') {
                $chObfs = !empty($ch['obfs_key']) ? $ch['obfs_key'] : ($settings['obfs_key'] ?? '');
                if ($chObfs !== '') {
                    $item['obfs-key'] = $chObfs;
                }
            }
            $clientChannels[] = $item;
        }

        if (!empty($clientChannels)) {
            $proxy['channels'] = $clientChannels;
        } elseif (!empty($server['ports'])) {
            $proxy['channels'] = [
                [
                    'id' => 'ch-tcp',
                    'enabled' => true,
                    'ports' => (string) $server['ports'],
                    'transport' => 'tcp',
                    'role' => 'primary',
                    'weight' => 100,
                ],
                [
                    'id' => 'ch-udp',
                    'enabled' => true,
                    'ports' => (string) $server['ports'],
                    'transport' => 'udp',
                    'role' => 'primary',
                    'weight' => 100,
                ],
            ];
        }

        return $proxy;
    }

    private static function extractDestHost(string $dest): string
    {
        $trimmed = trim($dest);
        if ($trimmed === '') {
            return '';
        }
        if (str_starts_with($trimmed, '[')) {
            $pos = strpos($trimmed, ']');
            return $pos !== false ? substr($trimmed, 1, $pos - 1) : '';
        }
        if (substr_count($trimmed, ':') === 1) {
            [$host, $port] = explode(':', $trimmed, 2);
            if (ctype_digit($port)) {
                return trim($host);
            }
        }
        return $trimmed;
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
