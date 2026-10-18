<?php

namespace Tests\Unit;

use App\Http\Middleware\Admin;
use App\Http\Middleware\Staff;
use App\Http\Middleware\User as UserMiddleware;
use App\Services\AuthService;
use Firebase\JWT\JWT;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\HttpException;

class AuthServiceTest extends TestCase
{
    private $previousContainer;
    private $previousFacadeApplication;

    protected function setUp(): void
    {
        parent::setUp();

        $this->previousContainer = Container::getInstance();
        $this->previousFacadeApplication = Facade::getFacadeApplication();

        // Keep authentication tests isolated from application boot and real caches.
        $app = new Application(dirname(__DIR__, 2));
        $app->instance('config', new ConfigRepository([
            'app' => ['key' => 'isolated-auth-regression-test-signing-key'],
        ]));
        $app->instance('env', 'testing');

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        Cache::swap(new CacheRepository(new ArrayStore()));
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($this->previousFacadeApplication);
        Container::setInstance($this->previousContainer);

        parent::tearDown();
    }

    /**
     * @dataProvider invalidAuthorizationProvider
     */
    public function testInvalidAuthorizationIsRejected($authorization): void
    {
        $this->assertFalse(AuthService::decryptAuthData($authorization));
    }

    public static function invalidAuthorizationProvider(): array
    {
        return [
            'null' => [null],
            'empty string' => [''],
            'empty array' => [[]],
            'list of cache keys' => [['is_staff']],
            'staff default value' => [['is_staff' => 1]],
            'admin default value' => [['is_admin' => 1]],
            'user id default value' => [['id' => 900000000]],
            'integer' => [1],
            'boolean' => [true],
            'object' => [new \stdClass()],
        ];
    }

    /**
     * @dataProvider protectedMiddlewareProvider
     */
    public function testArrayAuthorizationCannotBypassMiddleware($middlewareClass, array $authorization): void
    {
        $request = Request::create('/auth-regression-test', 'GET', [
            'auth_data' => $authorization,
        ]);
        $nextCalled = false;

        try {
            (new $middlewareClass())->handle($request, function () use (&$nextCalled) {
                $nextCalled = true;
            });
        } catch (HttpException $exception) {
            $this->assertSame(403, $exception->getStatusCode());
            $this->assertFalse($nextCalled);
            return;
        }

        $this->fail('Unauthenticated array input reached a protected handler.');
    }

    public static function protectedMiddlewareProvider(): array
    {
        return [
            'staff' => [Staff::class, ['is_staff' => 1]],
            'admin' => [Admin::class, ['is_admin' => 1]],
            'user' => [UserMiddleware::class, ['id' => 900000000]],
        ];
    }

    public function testValidCachedJwtStillPassesAuthentication(): void
    {
        $jwt = JWT::encode([
            'id' => 900000000,
            'session' => 'synthetic-session',
        ], config('app.key'), 'HS256');
        $user = [
            'id' => 900000000,
            'email' => 'fixture@example.invalid',
            'is_admin' => 1,
            'is_staff' => 1,
        ];
        Cache::put($jwt, $user, 60);

        $this->assertSame($user, AuthService::decryptAuthData($jwt));

        foreach ([Staff::class, Admin::class, UserMiddleware::class] as $middlewareClass) {
            $request = Request::create('/auth-regression-test', 'GET', ['auth_data' => $jwt]);
            $result = (new $middlewareClass())->handle($request, function ($request) {
                return $request->input('user');
            });

            $this->assertSame($user, $result);
        }
    }

    public function testMalformedJwtIsRejected(): void
    {
        $this->assertFalse(AuthService::decryptAuthData('not-a-valid-jwt'));
    }

    public function testJwtWithoutARegisteredSessionIsRejected(): void
    {
        $jwt = JWT::encode([
            'id' => 900000001,
            'session' => 'unregistered-session',
        ], config('app.key'), 'HS256');

        $this->assertFalse(AuthService::decryptAuthData($jwt));
    }
}
