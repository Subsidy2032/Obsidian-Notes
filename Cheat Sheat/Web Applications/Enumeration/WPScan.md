Description: A tool for enumerating WordPress sites

Update database: `wpscan --update`

Enumerating themes: `wpscan --url [url] --enumerate t`

Enumerating plugins: `wpscan --url [url] --enumerate p`

Enumerating users: `wpscan --url [url] --enumerate u`

Enumerating vulnerabilities: `wpscan --url [url] --enumerate v[Another flag]`

Performing password attack: `wpscan –-url [url] –-passwords rockyou.txt –-usernames [user names]`

Adjusting WPScan's Aggressiveness (WAF): `--plugins-detection aggressive/passive`