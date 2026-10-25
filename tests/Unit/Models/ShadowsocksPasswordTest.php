<?php

namespace Tests\Unit\Models;

use App\Models\Server;
use App\Models\User;
use PHPUnit\Framework\TestCase;

class ShadowsocksPasswordTest extends TestCase
{
    public function test_chacha20_subscriptions_use_only_the_user_key(): void
    {
        $server = new Server();
        $server->setRawAttributes([
            'type' => 'shadowsocks',
            'protocol_settings' => json_encode(['cipher' => '2022-blake3-chacha20-poly1305']),
        ]);
        $user = new User(['uuid' => 'a3482e88-686a-4a58-8126-99c9df64b7bf']);

        $this->assertSame(
            'YTM0ODJlODgtNjg2YS00YTU4LTgxMjYtOTljOWRmNjQ=',
            $server->generateServerPassword($user),
        );
    }

    public function test_aes_subscriptions_keep_the_server_and_user_keys(): void
    {
        foreach (['2022-blake3-aes-128-gcm' => 16, '2022-blake3-aes-256-gcm' => 32] as $cipher => $length) {
            $server = new Server();
            $server->setRawAttributes([
                'type' => 'shadowsocks',
                'protocol_settings' => json_encode(['cipher' => $cipher]),
                'created_at' => '2026-10-25 00:00:00',
            ]);
            $user = new User(['uuid' => 'a3482e88-686a-4a58-8126-99c9df64b7bf']);
            $keys = explode(':', $server->generateServerPassword($user));

            $this->assertCount(2, $keys);
            foreach ($keys as $key) {
                $this->assertSame($length, strlen(base64_decode($key, true)));
            }
        }
    }
}
