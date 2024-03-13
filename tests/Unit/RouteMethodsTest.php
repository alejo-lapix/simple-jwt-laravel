<?php

declare(strict_types=1);

namespace Tests\Unit;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Lapix\SimpleJWTLaravel\RouteMethods;
use Lapix\SimpleJWTLaravel\RoutesOptions;
use Tests\TestCase;

class RouteMethodsTest extends TestCase
{
    public function testShouldAddTheRoutes(): void
    {
        $router = $this->app->get('router');
        $action = new RouteMethods($router);
        $action->addRoutes(new RoutesOptions(migration: []));

        $routes = $router->getRoutes()
                         ->toCompiledRouteCollection($router $this->app);

        $this->assertNotEmpty($routes->getByName('token.session.create'));
        $this->assertNotEmpty($routes->getByName('token.create'));
        $this->assertNotEmpty($routes->getByName('token.keys'));
        $this->assertNotEmpty($routes->getByName('token.create'));
        $this->assertNotEmpty($routes->getByName('token.revoke'));
        $this->assertNotEmpty($routes->getByName('token.refresh'));
    }
}
