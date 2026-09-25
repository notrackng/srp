<?php

declare(strict_types=1);

include_once dirname(__DIR__) . '/env.php';
load_env_file(dirname(__DIR__) . '/.env');

define('USE_USERNAME', true);
define('LOGOUT_URL', '#');
define('TIMEOUT_MINUTES', 0);
define('TIMEOUT_CHECK_ACTIVITY', true);
