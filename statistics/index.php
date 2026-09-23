<?php

declare(strict_types=1);

require_once __DIR__ . '/stat_path.php';

header('Location: ' . statUrl('/realtime/?date=rt_1'), true, 302);
exit;
