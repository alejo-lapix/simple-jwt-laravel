<?php

namespace Lapix\SimpleJWTLaravel;

class Router
{
    public function __construct(private \Psr\Container\ContainerInterface $app)
    {
    }

    public function routes(RoutesOptions $options): void
    {
        (new RouteMethods($this->app->get('router')))
            ->addRoutes($options);
    }
}
