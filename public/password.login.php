<?php

declare(strict_types=1);

include_once dirname(__DIR__) . '/env.php';
load_env_file(dirname(__DIR__) . '/.env');

define('ADMIN_PASSWORD', (string) app_env('ADMIN_PASSWORD', ''));
define('A2ROOT_PASSWORD', (string) app_env('A2ROOT_PASSWORD', ''));
define('USE_USERNAME', true);
define('LOGOUT_URL', '#');
define('TIMEOUT_MINUTES', 0);
define('TIMEOUT_CHECK_ACTIVITY', true);
