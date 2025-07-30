# Global IPconnect Access Control for WordPress

**Global IPconnect Access Control** is a lightweight WordPress plugin that detects and redirects visitors using known proxy, VPN, or hosting network IPs. It uses [proxycheck.io](https://proxycheck.io) to verify the visitor's IP and redirects suspicious traffic to a managed block page.

---

## Features

* Detects visitors using proxy, VPN, or hosting IP addresses
* Uses proxycheck.io API with 30-minute result caching
* Secure API key storage — not viewable or editable after initial setup
* Automatic redirection to a block page if proxy use is detected
* Simple setup process, no configuration needed afterward
* API queries tagged for identification in your proxycheck.io dashboard

---

## Requirements

* WordPress 5.0 or later
* PHP 7.2 or later
* An active [proxycheck.io](https://proxycheck.io) API key

---

## Installation

1. Upload the plugin ZIP via the WordPress Admin Dashboard or extract it manually into the `wp-content/plugins/` directory.
2. Activate the plugin.
3. You will be redirected to a one-time setup screen to enter your proxycheck.io API key.
4. Once saved, the API key is encrypted and cannot be retrieved or edited later.

---

## How It Works

* On each visitor request, the plugin checks if their IP is stored in the cache.
* If not cached, the plugin sends a secure query to proxycheck.io using your API key.
* If the visitor is flagged as using a proxy or VPN, they are redirected to:

  ```
  https://access.global-ipconnect.com/403/?from={original_full_requested_url}
  ```
* API responses are cached for 30 minutes to reduce API usage.

---

## Privacy

When a visitor is redirected, their original requested URL is passed as a query string to the Global IPconnect block page service. This redirect request originates from your domain and is logged by Global IPconnect.

### What is logged:

* IP address of the visitor
* Source domain
* Requested URL path

### How logs are used:

* Logs are reviewed only to ensure that valid IP addresses are not being misclassified or blocked in error.
* Logs are not sold, shared, or used for marketing, analytics, or behavioral tracking.
* Logs are periodically purged to minimize retention.

Global IPconnect adheres to strong privacy and data minimization practices.

---

## Security

* The API key is encrypted using AES-256-CBC and stored in the database.
* The encryption key is derived from a random salt stored securely in the plugin directory.
* The plugin enforces a strict one-time API key setup to prevent exposure in the admin UI.

---

## Uninstall Behavior

* On plugin uninstall, all plugin settings — including the encrypted API key and salt — are removed from the database and file system.
* Reinstalling the plugin will require you to re-enter your API key during setup.

---

## Support

This plugin is maintained by Global IPconnect. For help or questions, please open an issue or contact support through your existing channels.
