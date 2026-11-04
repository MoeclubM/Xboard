<?php

namespace Tests\Unit;

use App\Protocols\ClashMeta;
use App\Support\FluxConfig;
use Illuminate\Http\Request;
use Tests\TestCase;

class FluxCapabilityTest extends TestCase
{
    public function test_flux_is_explicit_and_never_assumed_from_clash_format(): void
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
            $this->assertCount($expected ? 1 : 0, $protocol->selected());
        }
    }
}
