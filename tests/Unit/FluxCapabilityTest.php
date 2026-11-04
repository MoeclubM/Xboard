<?php

namespace Tests\Unit;

use App\Protocols\ClashMeta;
use App\Protocols\Aerion;
use App\Support\ProtocolManager;
use App\Support\FluxConfig;
use Illuminate\Http\Request;
use Tests\TestCase;

class FluxCapabilityTest extends TestCase
{
    public function test_channel_can_enable_certificate_verification_over_an_insecure_default(): void
    {
        $proxy = FluxConfig::toClientProxy('credential', [
            'name' => 'Flux', 'host' => 'edge.example.com', 'port' => 443,
            'protocol_settings' => [
                'security' => 'tls', 'tls_settings' => ['allow_insecure' => true],
                'channels' => [
                    ['id' => 'inherit'],
                    ['id' => 'verified', 'allow_insecure' => false],
                    ['id' => 'insecure', 'allow_insecure' => true],
                ],
            ],
        ]);
        $this->assertTrue($proxy['skip-cert-verify']);
        $this->assertArrayNotHasKey('skip-cert-verify', $proxy['channels'][0]);
        $this->assertFalse($proxy['channels'][1]['skip-cert-verify']);
        $this->assertTrue($proxy['channels'][2]['skip-cert-verify']);
    }

    public function test_mihomo_never_exports_flux_even_with_an_explicit_capability(): void
    {
        foreach ([
            ['Mihomo/1.19.0', '', '', false],
            ['Clash.Meta/1.19.0', 'all', '', false],
            ['Clash-Verge/2.5.0', '', '', false],
            ['Aerion/0.1', '', '', true],
            ['XBClient/0.1', '', '', true],
            ['Aerion/0.1', 'vless,sudoku', '', false],
            ['Aerion/0.1', '', 'sudoku', false],
            ['Mihomo/1.19.0', 'vless,flux', '', true],
            ['', '', 'sudoku,flux', true],
        ] as [$agent, $types, $protocols, $expected]) {
            $request = Request::create('/subscribe', 'GET', $types === '' ? [] : ['types' => $types]);
            $request->headers->set('X-XBClient-Protocols', $protocols);
            $this->app->instance('request', $request);
            $this->assertSame($expected, FluxConfig::supportsClient($request, $agent));
            $protocol = new class([], [['type' => 'flux', 'name' => 'flux-node']], null, null, $agent) extends ClashMeta {
                public function selected(): array { return $this->servers; }
            };
            $this->assertCount(0, $protocol->selected());
        }
    }

    public function test_aerion_has_its_own_flags_and_capability_filter(): void
    {
        $manager = new ProtocolManager($this->app);
        $this->assertSame(Aerion::class, $manager->matchProtocolClassName('aerion'));
        $this->assertSame(Aerion::class, $manager->matchProtocolClassName('XBClient/0.1'));
        $this->assertSame(ClashMeta::class, $manager->matchProtocolClassName('Mihomo/1.19.22'));
        $this->assertSame(ClashMeta::class, $manager->matchProtocolClassName('meta'));

        foreach ([['', '', true], ['all', '', true], ['flux', '', true],
            ['vless,sudoku', 'flux', false], ['', 'sudoku', false], ['', 'sudoku,flux', true]]
            as [$types, $header, $expected]) {
            $request = Request::create('/subscribe', 'GET', ['flag' => 'aerion', 'types' => $types]);
            $request->headers->set('X-XBClient-Protocols', $header);
            $this->app->instance('request', $request);
            $protocol = new class([], [['type' => 'flux', 'name' => 'Flux']], 'aerion') extends Aerion {
                public function selected(): array { return $this->servers; }
            };
            $this->assertCount($expected ? 1 : 0, $protocol->selected());
        }
    }

    public function test_aerion_keeps_standard_builders_and_owns_flux_serialization(): void
    {
        $this->app->instance('request', Request::create('/subscribe'));
        $aerion = new class([], [], 'aerion') extends Aerion {
            public function proxy(array $server): ?array { return $this->buildProxy($server); }
        };
        $mihomo = new class([], []) extends ClashMeta {
            public function proxy(array $server): ?array { return $this->buildProxy($server); }
        };
        $server = ['type' => 'flux', 'name' => 'Flux', 'host' => 'edge.example.com', 'port' => 443,
            'password' => 'credential', 'protocol_settings' => ['security' => 'obfs', 'obfs_key' => 'secret']];
        $this->assertNull($mihomo->proxy($server));
        $this->assertSame(FluxConfig::toClientProxy('credential', $server), $aerion->proxy($server));
        $server['type'] = 'http';
        $this->assertSame($mihomo->proxy($server), $aerion->proxy($server));
    }
}
