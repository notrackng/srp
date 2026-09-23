<?php

declare(strict_types=1);

// Delegates to the root unified PDO connection.
// Kept as a compatibility shim — all files in redirect/ still
// use `$pdo = require __DIR__ . '/connection.config.php';`.

return require __DIR__ . '/../connection_pdo.php';
