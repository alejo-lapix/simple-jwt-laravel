<?php

namespace Lapix\SimpleJWTLaravel;

use Illuminate\Routing\Router;
use Lapix\SimpleJWTLaravel\Http\Controllers\JWTController;

class RouteMethods
{
    public function __construct(private Router $router)
    {
    }

    public function addRoutes(RoutesOptions $options): void
    {
        $this->addMigrationRoutes($options);
        $this->addDiscoveryRoutes($options);
        $this->addAuthenticatingRoutes($options);
        $this->addManagementRoutes($options);
    }

    private function defaultOptions(): array
    {
        return ['controller' => JWTController::class];
    }

    private function addMigrationRoutes(RoutesOptions $options): void
    {
        $migrationOptions = $options->migration ?? null;
        if ($migrationOptions === null) {
            return;
        }

        $migrationOptions = array_merge($this->defaultOptions(), $migrationOptions);

        $this->router->group($migrationOptions, function (Router $router) {
            $router->post(
                '/token/create-from-session',
                'createTokenFromSession',
            )
                ->name('token.session.create');
        });
    }

    private function addDiscoveryRoutes(RoutesOptions $options): void
    {
        $discoveryOptions = array_merge($this->defaultOptions(), $options->discovery ?? []);

        $this->router->group($discoveryOptions, function ($router) {
            $router->get('/jwt/keys', 'keys')
                ->name('token.keys');
        });
    }

    private function addAuthenticatingRoutes(RoutesOptions $options): void
    {
        $authOptions = array_merge($this->defaultOptions(), $options->authenticating ?? []);

        $this->router->group($authOptions, function ($router) {
            $router->post('/token/create', 'create')
                ->name('token.create');
        });
    }

    private function addManagementRoutes(RoutesOptions $options): void
    {
        $managementOptions = array_merge($this->defaultOptions(), $options->management ?? []);

        $this->router->group($managementOptions, function ($router) {
            $router->post('/token/revoke', 'revoke')
                ->name('token.revoke');

            $router->post('/token/refresh', 'refresh')
                ->name('token.refresh');
        });
    }
}
