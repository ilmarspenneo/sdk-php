<?php

namespace Penneo\SDK\Tests\Unit\OAuth;

use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use Penneo\SDK\OAuth\Config\OAuthConfig;
use Penneo\SDK\OAuth\OAuthApi;
use Penneo\SDK\OAuth\Tokens\PenneoTokens;
use Penneo\SDK\OAuth\Tokens\SessionTokenStorage;
use Penneo\SDK\OAuth\UniqueIdGenerator;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

class OAuthApiTest extends TestCase
{
    use TestsEnvironments;

    private $config;
    private $client;
    private $api;
    /** @var UniqueIdGenerator&Stub */
    private $idGenerator;

    public function setUp(): void
    {
        Carbon::setTestNow(Carbon::now());

        $this->config = $this->createPartialMock(
            OAuthConfig::class,
            ['getClientSecret', 'getRedirectUri', 'getClientId', 'getEnvironment', 'getApiKey', 'getApiSecret']
        );
        $this->config->method('getClientSecret')->willReturn('secret');
        $this->config->method('getRedirectUri')->willReturn('https://google.com');
        $this->config->method('getClientId')->willReturn('id');
        $this->config->method('getApiKey')->willReturn('apiKey');

        $storage = $this->createMock(SessionTokenStorage::class);
        $this->client = $this->createMock(Client::class);
        $this->idGenerator = $this->createStub(UniqueIdGenerator::class);

        $this->api = new OAuthApi($this->config, $storage, $this->client, $this->idGenerator);

        $storage->method('getTokens')
            ->willReturn(new PenneoTokens(
                'not_important',
                'refresh_token',
                10,
                20
            ));

        parent::setUp();
    }

    /** @dataProvider environmentAndApiMethodProvider */
    public function testAPICallsUseCorrectHostname(string $env, string $expected, string $method, array $params = [])
    {
        $this->config->method('getEnvironment')->willReturn($env);

        $this->client->expects($this->once())
            ->method('post')
            ->with("https://{$expected}/oauth/token")
            ->willReturn($this->successfulResponse());

        $this->api->{$method}(...$params);
    }

    public function environmentAndApiMethodProvider(): \Generator
    {
        foreach (self::environmentProvider() as $case) {
            yield array_merge($case, ['postTokenRefresh']);
            yield array_merge($case, ['postCodeExchange', ['code', 'verifier']]);
            yield array_merge($case, ['postApiKeyExchange']);
        }
    }

    /**
     * @testWith ["unique id", "secret"]
     *           ["another unique id", "real secret"]
     */
    public function testApiKeysExchangeGeneratesProperParameters(string $mockUniqueId, string $apiSecret)
    {
        $this->config->method('getEnvironment')->willReturn('sandbox');
        $this->idGenerator->method('generate')->willReturn($mockUniqueId);
        $this->config->method('getApiSecret')->willReturn($apiSecret);

        $createdAt = Carbon::getTestNow()->toString();
        $nonce = substr(hash('sha512', $mockUniqueId), 0, 64);;
        $digest = base64_encode(sha1($nonce . $createdAt . $apiSecret, true));

        $this->client->expects($this->once())
            ->method('post')
            ->with("https://sandbox.oauth.penneo.cloud/oauth/token", [
                'json' => [
                    'grant_type' => 'api_keys',
                    'client_id' => 'id',
                    'client_secret' => 'secret',
                    'key' => 'apiKey',
                    'created_at' => Carbon::getTestNow()->toString(),
                    'nonce' => $nonce,
                    'digest' => $digest
                ]
            ])
            ->willReturn($this->successfulResponse());

        $this->api->postApiKeyExchange();
    }

    public function successfulResponse(): Response
    {
        return new Response(
            200,
            [],
            json_encode([
                'refresh_token' => '',
                'access_token' => '',
                'access_token_expires_at' => 5,
                'refresh_token_expires_at' => 20
            ])
        );
    }
}
