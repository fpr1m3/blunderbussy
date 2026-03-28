#!/bin/sh
# Auto-install Drupal 8 with SQLite so Drupalgeddon2 exploit endpoints are available.
# Without this, all requests redirect to /core/install.php and /user/register is unreachable.

echo "[drupal-setup] Preparing directories..."
chmod -R 777 /var/www/html/sites/default/files 2>/dev/null
mkdir -p /var/www/html/sites/default/files
chmod 777 /var/www/html/sites/default /var/www/html/sites/default/files
cp /var/www/html/sites/default/default.settings.php /var/www/html/sites/default/settings.php 2>/dev/null
chmod 666 /var/www/html/sites/default/settings.php

echo "[drupal-setup] Installing Drupal with SQLite..."
php -r '
chdir("/var/www/html");
$autoloader = require_once "autoload.php";
require_once "core/includes/install.core.inc";
$settings = [
  "parameters" => ["profile" => "standard", "langcode" => "en"],
  "forms" => [
    "install_settings_form" => [
      "driver" => "sqlite",
      "sqlite" => ["database" => "sites/default/files/.ht.sqlite"],
    ],
    "install_configure_form" => [
      "site_name" => "Drupal",
      "site_mail" => "admin@example.com",
      "account" => [
        "name" => "admin",
        "mail" => "admin@example.com",
        "pass" => ["pass1" => "admin", "pass2" => "admin"],
      ],
      "update_status_module" => [1 => true],
    ],
  ],
];
install_drupal($autoloader, $settings);
'

echo "[drupal-setup] Fixing permissions..."
chown -R www-data:www-data /var/www/html/sites/default/files
chmod -R 775 /var/www/html/sites/default/files
chown www-data:www-data /var/www/html/sites/default/settings.php

echo "[drupal-setup] Installation complete"
