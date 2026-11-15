<?php

namespace Tests\Unit;

use App\Models\Server;
use App\Protocols\Aerion;
use App\Protocols\ClashMeta;
use App\Support\ProtocolManager;
use Tests\TestCase;

class AerionProtocolTest extends TestCase
{
    public function test_flux_and_sudoku_are_excluded_from_valid_server_types(): void
    {
        $this->assertNotContains('flux', Server::VALID_TYPES);
        $this->assertNotContains('sudoku', Server::VALID_TYPES);
    }

    public function test_aerion_has_its_own_flags_and_keeps_standard_builders(): void
    {
        $manager = new ProtocolManager($this->app);
        $this->assertFalse(is_subclass_of(Aerion::class, ClashMeta::class));
        $this->assertSame(Aerion::class, $manager->matchProtocolClassName('aerion'));
        $this->assertSame(Aerion::class, $manager->matchProtocolClassName('XBClient/0.1'));
        $this->assertSame(Aerion::class, $manager->matchProtocolClassName('Neto/0.0.9'));
        $this->assertSame(ClashMeta::class, $manager->matchProtocolClassName('Mihomo/1.19.22'));
        $this->assertSame(ClashMeta::class, $manager->matchProtocolClassName('meta'));

        $aerion = new class([], [], 'aerion') extends Aerion {
            public function proxy(array $server): ?array { return $this->buildProxy($server); }
        };
        $mihomo = new class([], []) extends ClashMeta {
            public function proxy(array $server): ?array { return $this->buildProxy($server); }
        };

        $server = [
            'type' => 'http',
            'name' => 'HTTP',
            'host' => 'edge.example.com',
            'port' => 443,
            'password' => 'credential',
            'protocol_settings' => ['tls' => 1, 'tls_settings' => ['server_name' => 'edge.example.com']],
        ];
        $this->assertSame($mihomo->proxy($server), $aerion->proxy($server));
    }
}
