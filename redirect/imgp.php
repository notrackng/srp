<?php

/**
 * Image proxy entry point (redirect module).
 *
 * Thin shim — all logic lives in the shared handler so the public and redirect
 * copies can never drift. Do not inline logic here; edit imgp_handler.php.
 *
 * Usage: /imgp?u=<base64url-encoded-image-url>
 */

declare(strict_types=1);

require __DIR__ . '/../imgp_handler.php';
