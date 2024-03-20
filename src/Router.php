<?php

namespace Lapix\SimpleJWTLaravel;

class Router
{
    public function __construct(private mixed $app)
    {
    }

    public function routes(RoutesOptions $options): void
    {
        (new RouteMethods($this->app->get('router')))
            ->addRoutes($options);
    }
}
