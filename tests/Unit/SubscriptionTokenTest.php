<?php

namespace Tests\Unit;

use App\Exceptions\ApiException;
use App\Http\Middleware\Client;
use App\Models\User;
use App\Utils\Helper;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Auth;
use Tests\TestCase;

class SubscriptionTokenTest extends TestCase
{
    use RefreshDatabase;

    public function test_route_token_cannot_be_replaced_by_a_query_token(): void
    {
        $user = User::create([
            'email' => 'subscription-token@example.com', 'password' => 'password',
            'uuid' => Helper::guid(true), 'token' => str_repeat('a', 32),
        ]);
        $request = Request::create('/subscription/' . $user->token, 'GET', ['token' => ['invalid']]);
        $route = (new Route('GET', '/subscription/{token}', fn() => null))->bind($request);
        $request->setRouteResolver(fn() => $route);

        $id = (new Client())->handle($request, fn() => Auth::id());
        $this->assertSame($user->id, $id);
    }

    public function test_non_string_query_token_is_rejected_before_authentication(): void
    {
        $this->expectException(ApiException::class);
        (new Client())->handle(Request::create('/subscription', 'GET', ['token' => ['invalid']]),
            fn() => $this->fail('Malformed token reached the authenticated handler'));
    }
}
