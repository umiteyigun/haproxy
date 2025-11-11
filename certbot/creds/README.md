# DNS Provider Credentials

Bu klasöre DNS provider credentials dosyalarını ekleyin.

## Cloudflare

`cloudflare.ini` dosyası oluşturun:

```ini
dns_cloudflare_api_token = YOUR_API_TOKEN
```

VEYA

```ini
dns_cloudflare_email = your@email.com
dns_cloudflare_api_key = YOUR_API_KEY
```

## AWS Route53

`route53.ini` dosyası oluşturun:

```ini
dns_route53_access_key_id = YOUR_ACCESS_KEY
dns_route53_secret_access_key = YOUR_SECRET_KEY
```

## DigitalOcean

`digitalocean.ini` dosyası oluşturun:

```ini
dns_digitalocean_token = YOUR_API_TOKEN
```

## GoDaddy

`godaddy.ini` dosyası oluşturun:

```ini
dns_godaddy_api_key = YOUR_API_KEY
dns_godaddy_api_secret = YOUR_API_SECRET
```

## Hurricane Electric (HE.net)

`he-net.ini` dosyası oluşturun:

```ini
dns_he_net_api_key = YOUR_API_KEY
```

## OVH

`ovh.ini` dosyası oluşturun:

```ini
dns_ovh_endpoint = ovh-eu
dns_ovh_application_key = YOUR_APPLICATION_KEY
dns_ovh_application_secret = YOUR_APPLICATION_SECRET
dns_ovh_consumer_key = YOUR_CONSUMER_KEY
```

## Google Cloud DNS

`google.ini` dosyası oluşturun:

```ini
dns_google_credentials = /path/to/service-account.json
```

## DNSimple

`dnsimple.ini` dosyası oluşturun:

```ini
dns_dnsimple_token = YOUR_API_TOKEN
```

## RFC2136 (Generic DNS)

`rfc2136.ini` dosyası oluşturun:

```ini
dns_rfc2136_server = YOUR_DNS_SERVER
dns_rfc2136_name = YOUR_TSIG_KEY_NAME
dns_rfc2136_secret = YOUR_TSIG_KEY_SECRET
dns_rfc2136_algorithm = HMAC-SHA512
```

## Dosya İzinleri

Tüm credentials dosyaları için güvenlik amacıyla 600 izinleri ayarlayın:

```bash
chmod 600 *.ini
```

