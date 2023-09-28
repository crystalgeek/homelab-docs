![ntfy logo](./images/ntfy.png "ping ntfy!")

# ntfy install on Debian Linux

This is a quick and easy guide to get an ntfy server running and ready to forward push notifications to an Android and iOS device and the ntfy CLI.

#### Software and hardware specification for the server build:

* Hostname: LAB-UXA0001
* Operating System: Debian GNU/Linux 12.1 (bullseye)
* RAM: 1GiB
* Storage: x1 VHDX @ 5GiB
* Network: Hyper-V Network Adapter using DHCP
* Hyper-V Switch: External
* DVD Drive for ISO
* Bootloader: GRUB
* Extra packages in build:
    * sudo
    * curl

## Installation of the ntfy server service:

1. Download and install the latest .deb file from the [GitHub repository](https://github.com/binwiederhier/ntfy/releases/tag/v2.7.0): 
```bash
$ curl -L --output ~/ntfy_2.7.0_linux_amd64.deb https://github.com/binwiederhier/ntfy/releases/download/v2.7.0/ntfy_2.7.0_linux_amd64.deb
$ sudo dpkg -i ~/ntfy_*.deb
```

2. Start the service and enable at boot:

```bash
$ sudo systemctl enable ntfy --now
```

3. Now confirm the server is now running and bount to TCP port 80:

```bash
$ sudo systemctl status ntfy
$ sudo ss -antlp | grep -i --colour 'ntfy'
```

4. Now configure using a basic config file at `/etc/ntfy/server.yml`, we'll configure the below:

    - `base-url`: External URL of the ntfy server.
    - `listen-https`: Port associated with HTTPS traffic.
    - `listen-http`: Port associated with HTTP traffic.
    - `key-file`: Private key file.
    - `cert-file`: Certificate location.
    - `cache-file`: Cache for storing messages for a short period of time, beneficial for devices with poor network performance. Default is in-memory and at 12h.

```text
# ntfy server config file
#
# Please refer to the documentation at https://ntfy.sh/docs/config/ for details.
# All options also support underscores (_) instead of dashes (-) to comply with the YAML spec.

# Public facing base URL of the service (e.g. https://ntfy.sh or https://ntfy.example.com)
#
# This setting is required for any of the following features:
# - attachments (to return a download URL)
# - e-mail sending (for the topic URL in the email footer)
# - iOS push notifications for self-hosted servers (to calculate the Firebase poll_request topic)
# - Matrix Push Gateway (to validate that the pushkey is correct)
#
base-url: "https://LAB-UXSA001"

# Listen address for the HTTP & HTTPS web server. If "listen-https" is set, you must also
# set "key-file" and "cert-file". Format: [<ip>]:<port>, e.g. "1.2.3.4:8080".
#
# To listen on all interfaces, you may omit the IP address, e.g. ":443".
# To disable HTTP, set "listen-http" to "-".
#
listen-http: ":80"
listen-https: ":443"

# Listen on a Unix socket, e.g. /var/lib/ntfy/ntfy.sock
# This can be useful to avoid port issues on local systems, and to simplify permissions.
#
# listen-unix: <socket-path>
# listen-unix-mode: <linux permissions, e.g. 0700>

# Path to the private key & cert file for the HTTPS web server. Not used if "listen-https" is not set.
#
key-file: "/etc/ntfy/private.key"
cert-file: "/etc/ntfy/certificate.pem"

# If set, also publish messages to a Firebase Cloud Messaging (FCM) topic for your app.
# This is optional and only required to save battery when using the Android app.
#
# firebase-key-file: <filename>

# If "cache-file" is set, messages are cached in a local SQLite database instead of only in-memory.
# This allows for service restarts without losing messages in support of the since= parameter.
#
# The "cache-duration" parameter defines the duration for which messages will be buffered
# before they are deleted. This is required to support the "since=..." and "poll=1" parameter.
# To disable the cache entirely (on-disk/in-memory), set "cache-duration" to 0.
# The cache file is created automatically, provided that the correct permissions are set.
#
# The "cache-startup-queries" parameter allows you to run commands when the database is initialized,
# e.g. to enable WAL mode (see https://phiresky.github.io/blog/2020/sqlite-performance-tuning/)).
# Example:
#    cache-startup-queries: |
#       pragma journal_mode = WAL;
#       pragma synchronous = normal;
#       pragma temp_store = memory;
#       pragma busy_timeout = 15000;
#       vacuum;
#
# The "cache-batch-size" and "cache-batch-timeout" parameter allow enabling async batch writing
# of messages. If set, messages will be queued and written to the database in batches of the given
# size, or after the given timeout. This is only required for high volume servers.
#
# Debian/RPM package users:
#   Use /var/cache/ntfy/cache.db as cache file to avoid permission issues. The package
#   creates this folder for you.
#
# Check your permissions:
#   If you are running ntfy with systemd, make sure this cache file is owned by the
#   ntfy user and group by running: chown ntfy.ntfy <filename>.
#
cache-file: "/var/cache/ntfy/cache.db"
# cache-duration: "12h"
# cache-startup-queries:
# cache-batch-size: 0
# cache-batch-timeout: "0ms"

# If set, access to the ntfy server and API can be controlled on a granular level using
# the 'ntfy user' and 'ntfy access' commands. See the --help pages for details, or check the docs.
#
# - auth-file is the SQLite user/access database; it is created automatically if it doesn't already exist
# - auth-default-access defines the default/fallback access if no access control entry is found; it can be
#   set to "read-write" (default), "read-only", "write-only" or "deny-all".
# - auth-startup-queries allows you to run commands when the database is initialized, e.g. to enable
#   WAL mode. This is similar to cache-startup-queries. See above for details.
#
# Debian/RPM package users:
#   Use /var/lib/ntfy/user.db as user database to avoid permission issues. The package
#   creates this folder for you.
#
# Check your permissions:
#   If you are running ntfy with systemd, make sure this user database file is owned by the
#   ntfy user and group by running: chown ntfy.ntfy <filename>.
#
# auth-file: <filename>
# auth-default-access: "read-write"
# auth-startup-queries:

# If set, the X-Forwarded-For header is used to determine the visitor IP address
# instead of the remote address of the connection.
#
# WARNING: If you are behind a proxy, you must set this, otherwise all visitors are rate limited
#          as if they are one.
#
# behind-proxy: false

# If enabled, clients can attach files to notifications as attachments. Minimum settings to enable attachments
# are "attachment-cache-dir" and "base-url".
#
# - attachment-cache-dir is the cache directory for attached files
# - attachment-total-size-limit is the limit of the on-disk attachment cache directory (total size)
# - attachment-file-size-limit is the per-file attachment size limit (e.g. 300k, 2M, 100M)
# - attachment-expiry-duration is the duration after which uploaded attachments will be deleted (e.g. 3h, 20h)
#
# attachment-cache-dir:
# attachment-total-size-limit: "5G"
# attachment-file-size-limit: "15M"
# attachment-expiry-duration: "3h"

# If enabled, allow outgoing e-mail notifications via the 'X-Email' header. If this header is set,
# messages will additionally be sent out as e-mail using an external SMTP server.
#
# As of today, only SMTP servers with plain text auth (or no auth at all), and STARTLS are supported.
# Please also refer to the rate limiting settings below (visitor-email-limit-burst & visitor-email-limit-burst).
#
# - smtp-sender-addr is the hostname:port of the SMTP server
# - smtp-sender-from is the e-mail address of the sender
# - smtp-sender-user/smtp-sender-pass are the username and password of the SMTP user (leave blank for no auth)
#
# smtp-sender-addr:
# smtp-sender-from:
# smtp-sender-user:
# smtp-sender-pass:

# If enabled, ntfy will launch a lightweight SMTP server for incoming messages. Once configured, users can send
# emails to a topic e-mail address to publish messages to a topic.
#
# - smtp-server-listen defines the IP address and port the SMTP server will listen on, e.g. :25 or 1.2.3.4:25
# - smtp-server-domain is the e-mail domain, e.g. ntfy.sh
# - smtp-server-addr-prefix is an optional prefix for the e-mail addresses to prevent spam. If set to "ntfy-",
#   for instance, only e-mails to ntfy-$topic@ntfy.sh will be accepted. If this is not set, all emails to
#   $topic@ntfy.sh will be accepted (which may obviously be a spam problem).
#
# smtp-server-listen:
# smtp-server-domain:
# smtp-server-addr-prefix:

# Web Push support (background notifications for browsers)
#
# If enabled, allows ntfy to receive push notifications, even when the ntfy web app is closed. When enabled, users
# can enable background notifications in the web app. Once enabled, ntfy will forward published messages to the push
# endpoint, which will then forward it to the browser.
#
# You must configure web-push-public/private key, web-push-file, and web-push-email-address below to enable Web Push.
# Run "ntfy webpush keys" to generate the keys.
#
# - web-push-public-key is the generated VAPID public key, e.g. AA1234BBCCddvveekaabcdfqwertyuiopasdfghjklzxcvbnm1234567890
# - web-push-private-key is the generated VAPID private key, e.g. AA2BB1234567890abcdefzxcvbnm1234567890
# - web-push-file is a database file to keep track of browser subscription endpoints, e.g. `/var/cache/ntfy/webpush.db`
# - web-push-email-address is the admin email address send to the push provider, e.g. `sysadmin@example.com`
# - web-push-startup-queries is an optional list of queries to run on startup`
#
# web-push-public-key:
# web-push-private-key:
# web-push-file:
# web-push-email-address:
# web-push-startup-queries:

# If enabled, ntfy can perform voice calls via Twilio via the "X-Call" header.
#
# - twilio-account is the Twilio account SID, e.g. AC12345beefbeef67890beefbeef122586
# - twilio-auth-token is the Twilio auth token, e.g. affebeef258625862586258625862586
# - twilio-phone-number is the outgoing phone number you purchased, e.g. +18775132586
# - twilio-verify-service is the Twilio Verify service SID, e.g. VA12345beefbeef67890beefbeef122586
#
# twilio-account:
# twilio-auth-token:
# twilio-phone-number:
# twilio-verify-service:

# Interval in which keepalive messages are sent to the client. This is to prevent
# intermediaries closing the connection for inactivity.
#
# Note that the Android app has a hardcoded timeout at 77s, so it should be less than that.
#
# keepalive-interval: "45s"

# Interval in which the manager prunes old messages, deletes topics
# and prints the stats.
#
# manager-interval: "1m"

# Defines topic names that are not allowed, because they are otherwise used. There are a few default topics
# that cannot be used (e.g. app, account, settings, ...). To extend the default list, define them here.
#
# Example:
#   disallowed-topics:
#     - about
#     - pricing
#     - contact
#
# disallowed-topics:

# Defines the root path of the web app, or disables the web app entirely.
#
# Can be any simple path, e.g. "/", "/app", or "/ntfy". For backwards-compatibility reasons,
# the values "app" (maps to "/"), "home" (maps to "/app"), or "disable" (maps to "") to disable
# the web app entirely.
#
# web-root: /

# Various feature flags used to control the web app, and API access, mainly around user and
# account management.
#
# - enable-signup allows users to sign up via the web app, or API
# - enable-login allows users to log in via the web app, or API
# - enable-reservations allows users to reserve topics (if their tier allows it)
#
# enable-signup: false
# enable-login: false
# enable-reservations: false

# Server URL of a Firebase/APNS-connected ntfy server (likely "https://ntfy.sh").
#
# iOS users:
#   If you use the iOS ntfy app, you MUST configure this to receive timely notifications. You'll like want this:
#   upstream-base-url: "https://ntfy.sh"
#
# If set, all incoming messages will publish a "poll_request" message to the configured upstream server, containing
# the message ID of the original message, instructing the iOS app to poll this server for the actual message contents.
# This is to prevent the upstream server and Firebase/APNS from being able to read the message.
#
# - upstream-base-url is the base URL of the upstream server. Should be "https://ntfy.sh".
# - upstream-access-token is the token used to authenticate with the upstream server. This is only required
#   if you exceed the upstream rate limits, or the uptream server requires authentication.
#
# upstream-base-url:
# upstream-access-token:

# Rate limiting: Total number of topics before the server rejects new topics.
#
# global-topic-limit: 15000

# Rate limiting: Number of subscriptions per visitor (IP address)
#
# visitor-subscription-limit: 30

# Rate limiting: Allowed GET/PUT/POST requests per second, per visitor:
# - visitor-request-limit-burst is the initial bucket of requests each visitor has
# - visitor-request-limit-replenish is the rate at which the bucket is refilled
# - visitor-request-limit-exempt-hosts is a comma-separated list of hostnames, IPs or CIDRs to be
#   exempt from request rate limiting. Hostnames are resolved at the time the server is started.
#   Example: "1.2.3.4,ntfy.example.com,8.7.6.0/24"
#
# visitor-request-limit-burst: 60
# visitor-request-limit-replenish: "5s"
# visitor-request-limit-exempt-hosts: ""

# Rate limiting: Hard daily limit of messages per visitor and day. The limit is reset
# every day at midnight UTC. If the limit is not set (or set to zero), the request
# limit (see above) governs the upper limit.
#
# visitor-message-daily-limit: 0

# Rate limiting: Allowed emails per visitor:
# - visitor-email-limit-burst is the initial bucket of emails each visitor has
# - visitor-email-limit-replenish is the rate at which the bucket is refilled
#
# visitor-email-limit-burst: 16
# visitor-email-limit-replenish: "1h"

# Rate limiting: Attachment size and bandwidth limits per visitor:
# - visitor-attachment-total-size-limit is the total storage limit used for attachments per visitor
# - visitor-attachment-daily-bandwidth-limit is the total daily attachment download/upload traffic limit per visitor
#
# visitor-attachment-total-size-limit: "100M"
# visitor-attachment-daily-bandwidth-limit: "500M"

# Rate limiting: Enable subscriber-based rate limiting (mostly used for UnifiedPush)
#
# If enabled, subscribers may opt to have published messages counted against their own rate limits, as opposed
# to the publisher's rate limits. This is especially useful to increase the amount of messages that high-volume
# publishers (e.g. Matrix/Mastodon servers) are allowed to send.
#
# Once enabled, a client may send a "Rate-Topics: <topic1>,<topic2>,..." header when subscribing to topics via
# HTTP stream, or websockets, thereby registering itself as the "rate visitor", i.e. the visitor whose rate limits
# to use when publishing on this topic. Note: Setting the rate visitor requires READ-WRITE permission on the topic.
#
# UnifiedPush only: If this setting is enabled, publishing to UnifiedPush topics will lead to a HTTP 507 response if
# no "rate visitor" has been previously registered. This is to avoid burning the publisher's "visitor-message-daily-limit".
#
# visitor-subscriber-rate-limiting: false

# Payments integration via Stripe
#
# - stripe-secret-key is the key used for the Stripe API communication. Setting this values
#   enables payments in the ntfy web app (e.g. Upgrade dialog). See https://dashboard.stripe.com/apikeys.
# - stripe-webhook-key is the key required to validate the authenticity of incoming webhooks from Stripe.
#   Webhooks are essential up keep the local database in sync with the payment provider. See https://dashboard.stripe.com/webhooks.
# - billing-contact is an email address or website displayed in the "Upgrade tier" dialog to let people reach
#   out with billing questions. If unset, nothing will be displayed.
#
# stripe-secret-key:
# stripe-webhook-key:
# billing-contact:

# Metrics
#
# ntfy can expose Prometheus-style metrics via a /metrics endpoint, or on a dedicated listen IP/port.
# Metrics may be considered sensitive information, so before you enable them, be sure you know what you are
# doing, and/or secure access to the endpoint in your reverse proxy.
#
# - enable-metrics enables the /metrics endpoint for the default ntfy server (i.e. HTTP, HTTPS and/or Unix socket)
# - metrics-listen-http exposes the metrics endpoint via a dedicated [IP]:port. If set, this option implicitly
#   enables metrics as well, e.g. "10.0.1.1:9090" or ":9090"
#
# enable-metrics: false
# metrics-listen-http:

# Profiling
#
# ntfy can expose Go's net/http/pprof endpoints to support profiling of the ntfy server. If enabled, ntfy will listen
# on a dedicated listen IP/port, which can be accessed via the web browser on http://<ip>:<port>/debug/pprof/.
# This can be helpful to expose bottlenecks, and visualize call flows. See https://pkg.go.dev/net/http/pprof for details.
#
# profile-listen-http:

# Logging options
#
# By default, ntfy logs to the console (stderr), with an "info" log level, and in a human-readable text format.
# ntfy supports five different log levels, can also write to a file, log as JSON, and even supports granular
# log level overrides for easier debugging. Some options (log-level and log-level-overrides) can be hot reloaded
# by calling "kill -HUP $pid" or "systemctl reload ntfy".
#
# - log-format defines the output format, can be "text" (default) or "json"
# - log-file is a filename to write logs to. If this is not set, ntfy logs to stderr.
# - log-level defines the default log level, can be one of "trace", "debug", "info" (default), "warn" or "error".
#   Be aware that "debug" (and particularly "trace") can be VERY CHATTY. Only turn them on briefly for debugging purposes.
# - log-level-overrides lets you override the log level if certain fields match. This is incredibly powerful
#   for debugging certain parts of the system (e.g. only the account management, or only a certain visitor).
#   This is an array of strings in the format:
#      - "field=value -> level" to match a value exactly, e.g. "tag=manager -> trace"
#      - "field -> level" to match any value, e.g. "time_taken_ms -> debug"
#   Warning: Using log-level-overrides has a performance penalty. Only use it for temporary debugging.
#
# Check your permissions:
#   If you are running ntfy with systemd, make sure this log file is owned by the
#   ntfy user and group by running: chown ntfy.ntfy <filename>.
#
# Example (good for production):
#   log-level: info
#   log-format: json
#   log-file: /var/log/ntfy.log
#
# Example level overrides (for debugging, only use temporarily):
#   log-level-overrides:
#      - "tag=manager -> trace"
#      - "visitor_ip=1.2.3.4 -> debug"
#      - "time_taken_ms -> debug"
#
# log-level: info
# log-level-overrides:
# log-format: text
# log-file:
```

5. Restart the service once the `/etc/ntfy/server.yml` has been updated and the `private.key` file has been protected.

```bash
$ sudo chown ntfy:ntfy /etc/ntfy/private.key
$ sudo chmod 440 /etc/ntfy/private.key
$ sudo systemctl restart ntfy
```

## Installation of the ntfy client:

Both the client (ntfy CLI) and the server are contained in the same binary, however my client is running on Arch Linux AMD64 using WSL.

1. Install the client from the AUR:

```bash
$ yay -S --no-confirm ntfysh-bin
```

2. Since we are using our own server for this configuration we need to create the file `~/.config/ntfy/client.yml` and run as non-root user: 

    - `default-host`: Default host to send messages to.

```text
# ntfy client config file

# Base URL used to expand short topic names in the "ntfy publish" and "ntfy subscribe" commands.
# If you self-host a ntfy server, you'll likely want to change this.
#
default-host: https://LAB-UXA0001

# Default credentials will be used with "ntfy publish" and "ntfy subscribe" if no other credentials are provided.
# You can set a default token to use or a default user:password combination, but not both. For an empty password,
# use empty double-quotes ("").
#
# To override the default user:password combination or default token for a particular subscription (e.g., to send
# no Authorization header), set the user:pass/token for the subscription to empty double-quotes ("").

# default-token:

# default-user:
# default-password:

# Default command will execute after "ntfy subscribe" receives a message if no command is provided in subscription below
# default-command:

# Subscriptions to topics and their actions. This option is primarily used by the systemd service,
# or if you cann "ntfy subscribe --from-config" directly.
#
# Example:
#     subscribe:
#       - topic: mytopic
#         command: /usr/local/bin/mytopic-triggered.sh
#       - topic: myserver.com/anothertopic
#         command: 'echo "$message"'
#         if:
#             priority: high,urgent
#       - topic: secret
#         command: 'notify-send "$m"'
#         user: phill
#         password: mypass
#       - topic: token_topic
#         token: tk_AgQdq7mVBoFD37zQVN29RhuMzNIz2
#
# Variables:
#     Variable        Aliases               Description
#     --------------- --------------------- -----------------------------------
#     $NTFY_ID        $id                   Unique message ID
#     $NTFY_TIME      $time                 Unix timestamp of the message delivery
#     $NTFY_TOPIC     $topic                Topic name
#     $NTFY_MESSAGE   $message, $m          Message body
#     $NTFY_TITLE     $title, $t            Message title
#     $NTFY_PRIORITY  $priority, $prio, $p  Message priority (1=min, 5=max)
#     $NTFY_TAGS      $tags, $tag, $ta      Message tags (comma separated list)
#     $NTFY_RAW       $raw                  Raw JSON message
#
# Filters ('if:'):
#     You can filter 'message', 'title', 'priority' (comma-separated list, logical OR)
#     and 'tags' (comma-separated list, logical AND). See https://ntfy.sh/docs/subscribe/api/#filter-messages.
#
# subscribe:
```

### Test our first message:

1. Subscribe to a topic:

```bash
# This will wait until you stop the process:
$ ntfy subscribe test-topic
```

2. Then in another session publish a message to the same topic:

```bash
$ ntfy publish test-topic "Test"
```

If a message is then pushed to the client and displayed in JSON then this is now complete. 

To simply test using libcurl:

1. Subscribe to the topic 

```bash

```

### Configure access control: 