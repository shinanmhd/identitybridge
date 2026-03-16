<?php

arch('source classes use strict types')
    ->expect('IgniteLabs\IdentityBridge')
    ->toUseStrictTypes();

arch('events have constructor')
    ->expect('IgniteLabs\IdentityBridge\Events')
    ->toHaveConstructor();

arch('middleware classes are in Http\Middleware namespace')
    ->expect('IgniteLabs\IdentityBridge\Http\Middleware')
    ->toBeClasses();

arch('exceptions extend RuntimeException')
    ->expect('IgniteLabs\IdentityBridge\Exceptions')
    ->toExtend(\RuntimeException::class);

arch('no debugging statements')
    ->expect('IgniteLabs\IdentityBridge')
    ->not->toUse(['dd', 'dump', 'var_dump', 'print_r', 'ray']);

arch('commands extend Illuminate Command')
    ->expect('IgniteLabs\IdentityBridge\Commands')
    ->toExtend(\Illuminate\Console\Command::class);
