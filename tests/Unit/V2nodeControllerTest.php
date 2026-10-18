<?php

namespace Tests\Unit;

use App\Http\Controllers\V1\Admin\Server\V2nodeController;
use App\Models\ServerV2node;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Facade;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory as ValidationFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\HttpException;

class V2nodeControllerTest extends TestCase
{
    private $previousContainer;
    private $previousFacadeApplication;
    private $previousConnectionResolver;
    private $previousEventDispatcher;

    protected function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('Node persistence tests require pdo_sqlite.');
        }

        $this->previousContainer = Container::getInstance();
        $this->previousFacadeApplication = Facade::getFacadeApplication();
        $this->previousConnectionResolver = Model::getConnectionResolver();
        $this->previousEventDispatcher = Model::getEventDispatcher();

        // Exercise the real validator and model without booting the application.
        $app = new Application(dirname(__DIR__, 2));
        $app->instance('config', new ConfigRepository());
        $app->instance('env', 'testing');
        $app->instance('validator', new ValidationFactory(new Translator(new ArrayLoader(), 'en'), $app));
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
        Model::unsetEventDispatcher();

        $responses = $this->createMock(ResponseFactory::class);
        $responses->method('make')->willReturnCallback(function ($content, $status = 200, $headers = []) {
            return new Response($content, $status, $headers);
        });
        $app->instance(ResponseFactory::class, $responses);

        $database = new Capsule($app);
        $database->addConnection(['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $database->bootEloquent();
        $database->getConnection()->getSchemaBuilder()->create('v2_server_v2node', function (Blueprint $table) {
            $table->increments('id');
            foreach ([
                'group_id', 'route_id', 'name', 'parent_id', 'host', 'listen_ip',
                'port', 'server_port', 'protocol', 'tls', 'tls_settings', 'flow',
                'network', 'network_settings', 'trusted_x_forwarded_for',
                'encryption', 'encryption_settings', 'disable_sni', 'udp_relay_mode',
                'zero_rtt_handshake', 'congestion_control', 'cipher', 'up_mbps',
                'down_mbps', 'obfs', 'obfs_password', 'padding_scheme', 'tags',
                'rate', 'show', 'sort', 'created_at', 'updated_at',
            ] as $column) {
                $table->text($column)->nullable();
            }
        });
    }

    protected function tearDown(): void
    {
        if ($this->previousContainer !== null) {
            if ($this->previousConnectionResolver !== null) {
                Model::setConnectionResolver($this->previousConnectionResolver);
            } else {
                Model::unsetConnectionResolver();
            }
            if ($this->previousEventDispatcher !== null) {
                Model::setEventDispatcher($this->previousEventDispatcher);
            } else {
                Model::unsetEventDispatcher();
            }
            Facade::clearResolvedInstances();
            Facade::setFacadeApplication($this->previousFacadeApplication);
            Container::setInstance($this->previousContainer);
        }

        parent::tearDown();
    }

    public function testRemoteCertificateAndLocalTlsFlagsAreSavedTogether(): void
    {
        $server = $this->saveNode([
            'network' => 'ws',
            'network_settings' => ['path' => '/synthetic'],
            'trusted_x_forwarded_for' => ['X-Forwarded-For', 'CF-Connecting-IP'],
            'tls_settings' => [
                'server_name' => 'certificate.example.invalid',
                'cert_mode' => 'remote',
                'reject_unknown_sni' => 'true',
                'allow_insecure' => 'false',
            ],
        ]);
        $tls = $server->tls_settings;

        $this->assertSame(1, $tls['reject_unknown_sni']);
        $this->assertSame(0, $tls['allow_insecure']);
        $this->assertTrue(openssl_x509_check_private_key($tls['tls_cert'], $tls['tls_key']));
        $this->assertSame(openssl_x509_fingerprint($tls['tls_cert'], 'sha256'), $tls['pinned_peer_cert_sha256']);
        $this->assertSame('certificate.example.invalid', openssl_x509_parse($tls['tls_cert'])['subject']['CN']);
        $this->assertSame(['X-Forwarded-For', 'CF-Connecting-IP'], $server->trusted_x_forwarded_for);
        $this->assertSame(['path' => '/synthetic'], $server->network_settings);
    }

    public function testEditingNodeKeepsExistingRemoteCertificateAndPin(): void
    {
        $server = $this->saveNode(['tls_settings' => ['cert_mode' => 'remote']]);
        $tls = $server->tls_settings;
        $updated = $this->saveNode([
            'id' => $server->id,
            'name' => 'renamed fixture',
            'tls_settings' => $tls,
        ]);

        $this->assertSame($tls, $updated->tls_settings);
        $this->assertSame('renamed fixture', $updated->name);
        $this->assertSame(1, ServerV2node::count());
    }

    /** @dataProvider mieruTransportProvider */
    public function testMieruTransportsRemainSupported($transport): void
    {
        $server = $this->saveNode(['protocol' => 'mieru', 'network' => $transport]);

        $this->assertSame('mieru', $server->protocol);
        $this->assertSame($transport, $server->network);
        $this->assertSame(0, (int) $server->tls);
        $this->assertNull($server->tls_settings);
    }

    public static function mieruTransportProvider(): array
    {
        return ['tcp' => ['tcp'], 'udp' => ['udp']];
    }

    public function testSudokuSettingsRemainSupported(): void
    {
        // Synthetic scalar one and the corresponding Ed25519 base point.
        $privateKey = '01' . str_repeat('00', 31);
        $publicKey = '58' . str_repeat('66', 31);
        $server = $this->saveNode([
            'protocol' => 'sudoku',
            'encryption_settings' => ['master_private_key' => $privateKey, 'master_public_key' => $publicKey],
        ]);

        $this->assertSame('sudoku', $server->protocol);
        $this->assertSame($privateKey, $server->encryption_settings['master_private_key']);
        $this->assertSame($publicKey, $server->encryption_settings['master_public_key']);
        $this->assertSame(0, (int) $server->tls);
    }

    public function testShadowTlsSettingsRemainSupported(): void
    {
        $server = $this->saveNode([
            'protocol' => 'shadowtls',
            'tls_settings' => ['server_name' => 'tls.example.invalid', 'allow_insecure' => 'false'],
        ]);

        $this->assertSame('shadowtls', $server->protocol);
        $this->assertSame('2022-blake3-aes-128-gcm', $server->cipher);
        $this->assertSame('tls.example.invalid', $server->tls_settings['server_name']);
        $this->assertSame(0, $server->tls_settings['allow_insecure']);
    }

    /** @dataProvider invalidTransportProvider */
    public function testInvalidTransportsAreStillRejected($protocol, $transport): void
    {
        try {
            $this->saveNode(['protocol' => $protocol, 'network' => $transport]);
        } catch (HttpException $exception) {
            $this->assertSame(422, $exception->getStatusCode());
            $this->assertSame(0, ServerV2node::count());
            return;
        }

        $this->fail('An invalid transport was persisted.');
    }

    public static function invalidTransportProvider(): array
    {
        return ['vless udp' => ['vless', 'udp'], 'mieru ws' => ['mieru', 'ws']];
    }

    private function saveNode(array $overrides): ServerV2node
    {
        $params = array_replace([
            'group_id' => [1],
            'name' => 'fixture node',
            'host' => 'node.example.invalid',
            'port' => '443',
            'server_port' => '10443',
            'protocol' => 'vless',
            'tls' => 1,
            'network' => 'tcp',
            'disable_sni' => 0,
            'zero_rtt_handshake' => 0,
            'rate' => 1,
        ], $overrides);
        $request = NodeSaveRequest::create('/node-merge-test', 'POST', $params);
        $response = (new V2nodeController())->save($request);

        $this->assertSame(200, $response->getStatusCode());
        return isset($params['id']) ? ServerV2node::findOrFail($params['id']) : ServerV2node::firstOrFail();
    }
}

class NodeSaveRequest extends Request
{
    public function validate(array $rules): array
    {
        return app('validator')->make($this->all(), $rules)->validate();
    }
}
