# Global IPconnect Access Control for WordPress

Global IPconnect Access Control is a WordPress security plugin that combines IP reputation checks from [proxycheck.io](https://proxycheck.io) with on-site request inspection, visitor logging, and optional early loading through WordPress must-use plugins.

It can:

- redirect visitors detected as proxy, VPN, hosting, datacenter, Tor, bot, scraper, or otherwise anonymous traffic;
- redirect outdated browsers to a managed upgrade notice page;
- inspect requests for common attack patterns before the page is rendered; and
- record detailed visitor activity for review in WordPress admin.

## Feature Summary

- Proxy, VPN, hosting, datacenter, VPS, Tor, bot, scraper, and anonymous IP detection via proxycheck.io.
- 30-minute IP result caching to reduce API usage.
- Short timeout cache to avoid repeated lookups during API timeouts.
- Outdated browser detection with redirect support to the Global IPconnect 426 page.
- Advanced threat detection for:
  - PHP code injection
  - SQL injection
  - requests for non-existent PHP files
  - malicious file uploads
  - XSS payloads
  - directory traversal attempts
  - recursively encoded base64 payloads
- Detailed visitor logging with request method, HTTP status, parsed user agent, reverse DNS hostname, suspicious request flag, threat metadata, referrer, sanitized request data, and selected request headers.
- Admin pages for Settings, Visitor Logs, and Threat Detection.
- Optional MU-plugin loader so the plugin can run before regular plugins.
- Encrypted API key storage with salt recovery if the salt file is missing.
- Automatic cleanup of old logs based on the configured retention window.

## Requirements

- WordPress 6.8 or later
- PHP 7.4 or later
- A valid proxycheck.io API key
- File system write access if you want the plugin to install the MU-plugin loader automatically

## Installation

1. Copy the plugin into `wp-content/plugins/access-control/`.
2. Activate the plugin from the WordPress admin Plugins screen.
3. On first activation, WordPress redirects you to the setup page.
4. Enter your proxycheck.io API key and save it.
5. Review the Threat Detection settings page and enable the detection engine if you want request inspection in addition to proxy/VPN blocking.

## Optional Early Loading via MU-Plugin

For security-first deployments, the plugin can install a must-use loader so it is loaded before regular plugins.

You can enable this from the Threat Detection page in WordPress admin. The loader file is:

`wp-content/mu-plugins/load-access-control-early.php`

Manual setup is also possible:

1. Create `wp-content/mu-plugins/` if it does not exist.
2. Copy `load-access-control-early.php` from this plugin into that directory.
3. Confirm the main plugin remains installed at `wp-content/plugins/access-control/index.php`.

## Admin Pages

After activation, the plugin adds a Global IPconnect menu with these pages:

- Settings: store or replace the proxycheck.io API key.
- Visitor Logs: review traffic, filter requests, inspect suspicious entries, and perform database upgrades for new log columns.
- Threat Detection: enable the detection engine, tune detection methods, manage whitelists, choose block behavior, configure notification email, and install or remove the MU-plugin loader.

The plugin also adds a Flush IP Cache button to the WordPress admin bar for administrators.

## How Request Handling Works

### IP reputation and browser checks

On frontend requests, the plugin:

1. Determines the client IP, with support for Cloudflare and common proxy headers.
2. Redirects outdated browsers to `https://access.global-ipconnect.com/426/` unless the request comes from a recognized search bot or WordPress updater.
3. Looks up the IP in the local cache.
4. If the cache is stale or missing, queries proxycheck.io.
5. Blocks or redirects traffic when the response indicates proxy, VPN, hosting, bot, Tor, scraper, anonymous, blacklist-modified, or similar high-risk attributes.

Proxycheck queries are tagged using the current site domain so they are easier to identify in the proxycheck.io dashboard.

### Threat detection

When the threat detection engine is enabled, it runs before normal access-control handling and can inspect:

- GET parameters
- POST parameters
- uploaded files
- requests for suspicious PHP paths

By default, the settings include support for:

- PHP injection detection
- SQL injection detection
- PHP scan detection
- file upload inspection
- XSS detection
- directory traversal detection
- recursive base64 decoding

Detected threats can either:

- be logged only;
- be blocked directly with a configurable HTTP status code; or
- be redirected to the managed Global IPconnect 403 page with the threat reason attached.

Critical and high-severity detections can also trigger email notifications.

## Visitor Logging

The visitor log is designed for review and triage, not just simple hit counting. Logged data can include:

- visit time
- full requested URL
- client IP address
- reverse DNS hostname
- raw and parsed user agent
- HTTP status code
- logged-in username or email, when available
- request method
- suspicious request flag
- threat detection flag, type, name, severity, and detail text
- referrer
- sanitized GET and POST data
- selected request headers

The Visitor Logs page supports filtering by IP, URL, username, HTTP code, request method, suspicious status, error status, and date range. It also exposes preset views for common investigations such as suspicious requests, form posts, 404s, REST requests, and XML-RPC traffic.

## Whitelisting and Bypass Controls

Threat Detection includes built-in bypass controls for trusted traffic:

- IP whitelist with single IP, CIDR, and wildcard support
- URL whitelist with exact match, wildcard, and `regex:` patterns
- form field whitelist for parameters that should not be inspected

These controls only affect the threat detection engine. They do not change proxycheck.io classifications.

## Data Handling and Privacy

When the plugin redirects a blocked visitor to Global IPconnect-managed pages, the original request URL is passed to the external service as a query parameter. This allows the remote block page to display context and log the event.

Within WordPress, the plugin stores visitor logs locally in custom database tables. Request payload logging is sanitized before storage to reduce exposure of sensitive information. Common personal, authentication, and payment-related fields are redacted or removed.

The visitor log retention period is configurable from the Threat Detection settings page. Set the retention value to `0` to disable automatic deletion.

## Security Notes

- The proxycheck.io API key is encrypted with AES-256-CBC before storage.
- The encryption salt is stored in both a WordPress option and a file so the plugin can recover gracefully if the file is deleted.
- Re-saving the API key regenerates the salt and updates the encrypted payload.
- If the visitor log schema is behind the current code version, the admin UI exposes upgrade actions for new logging columns.

## Uninstall Behavior

On uninstall, the plugin removes:

- the encrypted API key and setup flags;
- the stored salt option and salt files;
- the IP cache and visitor log tables;
- scheduled cleanup events; and
- plugin-specific transients and options.

If you used the MU-plugin loader, remove `wp-content/mu-plugins/load-access-control-early.php` if it still exists after uninstall.

## Support

This plugin is maintained by Global IPconnect. Use your normal support channel for deployment, API, or security review questions.
