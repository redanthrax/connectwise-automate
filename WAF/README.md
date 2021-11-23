# Notes

## Deploy Debian 11 Bullseye to Azure

After Azure Deployment is complete and you have ssh access.

```
sudo apt update && sudo apt upgrade -y
sudo apt install cron-apt
sudo apt install nginx
sudo unlink /etc/nginx/sites-enabled/default
```

## Create the nginx automate configuration file
```
sudo vim /etc/nginx/sites-available/automate.conf
```

## automate.conf contents

```
server {
    server_name 2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com;
    listen 80;
    listen [::]:80;
    access_log /var/log/nginx/automate-access.log;
    error_log /var/log/nginx/automate-error.log;
    location / {
        proxy_pass http://automate.company.com;
    }
}
```

## Complete the nginx setup

```
sudo ln -s /etc/nginx/sites-available/automate.conf /etc/nginx/sites-enabled/automate.conf
sudo nginx -t
sudo nginx -s reload
```

Browsing to the public IP of your new WAF should reveal the base site. If not verify port 80 is open on the network security group.

## Install/Setup certbot

```
sudo apt install python3-acme python3-certbot python3-mock python3-openssl python3-pkg-resources python3-pyparsing python3-zope.interface
sudo apt install python3-certbot-nginx
sudo certbot --nginx -d 2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com
sudo certbot renew --dry-run
```

Validate the dry run went well.

## Install the tools needed to build modsecurity

```
sudo apt-get install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev libmaxminddb-dev libssl-dev libxslt-dev libgd-dev
```

## Clone and build modsecurity

```
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
git submodule init
git submodule update
./build.sh
```

Errors during build 'no names found' etc are okay.

```
./configure
sudo make
sudo make install
sudo mkdir /etc/nginx/modsec/
sudo cp unicode.mapping /etc/nginx/modsec/unicode.mapping
```

## Setup the modSecurity connector for nginx

```
cd ~
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
sudo nginx -v
```

Match the modsecurity version output by nginx -v to the version download in the next section.

```
wget http://nginx.org/download/nginx-1.14.2.tar.gz
tar -xvzmf nginx-1.14.2.tar.gz
cd nginx-1.14.2
sudo nginx -V
```
This will output the build options nginx is using. Remove the '--add-dynamic-module' options. Add the modsecurity module. The final options will look like the section below.

```
--add-dynamic-module=../ModSecurity-nginx --with-cc-opt='-g -O2 -fdebug-prefix-map=/build/nginx-m1Thpq/nginx-1.14.2=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-stream_ssl_preread_module --with-mail=dynamic --with-mail_ssl_module
```
Run the following command to configure the modsecurity nginx options

```
./configure --add-dynamic-module=../ModSecurity-nginx --with-cc-opt='-g -O2 -fdebug-prefix-map=/build/nginx-m1Thpq/nginx-1.14.2=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --modules-path=/usr/lib/nginx/modules --http-client-body-temp-path=/var/lib/nginx/body --http-fastcgi-temp-path=/var/lib/nginx/fastcgi --http-proxy-temp-path=/var/lib/nginx/proxy --http-scgi-temp-path=/var/lib/nginx/scgi --http-uwsgi-temp-path=/var/lib/nginx/uwsgi --with-debug --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_v2_module --with-http_dav_module --with-http_slice_module --with-threads --with-http_addition_module --with-http_geoip_module=dynamic --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-stream_ssl_preread_module --with-mail=dynamic --with-mail_ssl_module
```

Make the modules and install

```
make modules
sudo cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules
```

## Edit the nginx configuration

```
sudo vim /etc/nginx/nginx.conf
```

Add the following line outside of any block in the configuration file.

```
load_module modules/ngx_http_modsecurity_module.so;
```

## Setup modsec rules

```
sudo wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
sudo mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
```

## Edit the modsec rules

```
sudo vim /etc/nginx/modsec/modsecurity.conf
```

Change SecRuleEngine on from DetectionOnly to SecRuleEngine On.

## Download/Setup the Core Ruleset
```
cd ~
wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.tar.gz
tar -xzvf v3.3.2.tar.gz
sudo mv coreruleset-3.3.2 /usr/local
sudo cp /usr/local/coreruleset-3.3.2/crs-setup.conf.example /usr/local/coreruleset-3.3.2/crs-setup.conf
sudo vim /etc/nginx/modsec/automate.conf
```

Add the following rules to the automate.conf file.

```
Include /etc/nginx/modsec/modsecurity.conf
Include /usr/local/coreruleset-3.3.2/crs-setup.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-901-INITIALIZATION.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-910-IP-REPUTATION.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-912-DOS-PROTECTION.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-913-SCANNER-DETECTION.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-921-PROTOCOL-ATTACK.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
Include /usr/local/coreruleset-3.3.2/rules/REQUEST-949-BLOCKING-EVALUATION.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-950-DATA-LEAKAGES.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-980-CORRELATION.conf
Include /usr/local/coreruleset-3.3.2/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
SecRule REQUEST_URI "/Labtech/ControlCenter.asmx" "id:1,phase:1,allow"
SecRule REQUEST_URI "\/cwa\/api\/v1\/computers\/.+\/scripthistory" "id:2,phase:1,allow"
SecRule REQUEST_URI "\/cwa\/api\/v1\/computers\/.+\/services" "id:3,phase:1,allow"
SecRule REQUEST_URI "\/cwa\/api\/v1\/computers\/.+\/scripthistory" "id:4,phase:1,allow"
```

Move example rules.

```
sudo mv /usr/local/coreruleset-3.3.2/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /usr/local/coreruleset-3.3.2/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
sudo mv /usr/local/coreruleset-3.3.2/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example /usr/local/coreruleset-3.3.2/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

## Add modsecurity to the file

```
sudo vim /etc/nginx/sites-available/automate.conf
```

```
server {
    server_name 2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/automate.conf;
    access_log /var/log/nginx/automate-access.log;
    error_log /var/log/nginx/automate-error.log;
    add_header Content-Security-Policy "default-src 'self' https://files.connectwise.com https://cdn.walkme.com https://ec.walkme.com https://papi.walkme.com; script-src 'self' 'sha256-xwcDQq3LkoHikGSTgoUZln/oiN3i07txuKAV7xjONnY=' https://cdn.walkme.com https://playerserver.walkme.com; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https://files.connectwise.com; font-src 'self' data:;" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options nosniff;
    location / {
        proxy_pass https://automate.company.com;
        proxy_pass_header Authorization;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        client_max_body_size 0;
        proxy_read_timeout 36000s;
        proxy_redirect off;
    }
    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
server {
    if ($host = 2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot
    server_name 2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com;
    listen 80;
    listen [::]:80;
    return 404; # managed by Certbot
}
```

Refresh the configuration

```
sudo nginx -t
sudo nginx -s reload
```

Remove HTTPS redirect from Automate web.config and restart IIS if that was done before.

System Dashboard > Redirector Config update Hostname to heartbeat.randomdomain.com.

Update the server in the Default Template under Automation > Templates > Agent Templates with https://2ab31043-4063-4657-bd5f-dc2558fd0020.randomdomain.com.

Wait for agents to update.

Update anything that accesses the Automate API.

Update all API access (Vendors, Scripts etc).

Lock down all traffic to the Automate server to only allow from the IP of the reverse proxy IP.

## OPTIONAL: Blocking traffic by country
Download "GeoLite2 Country" from here https://www.maxmind.com/en/accounts/584942/geoip/downloads you will make an account, it's free.

Transfer the file to your server (scp).

```
tar -xvzf GeoLite2-Country_20210720.tar.gz (your file name may be different)
cd GeoLite2-Country_20210720
sudo mkdir /usr/local/Geo
mv GeoLite2-Country.mmdb /usr/local/Geo
```

## Update /etc/nginx/modsec/modsecurity.conf

Add the following rules to the bottom of the configuration.

```
sudo vim /etc/nginx/modsec/modsecurity.conf
```

```
SecGeoLookupDb /usr/local/Geo/GeoLite2-Country.mmdb
SecRule REMOTE_ADDR "@geoLookup" "chain,id:668,drop,msg:'Non US IP address'"
SecRule GEO:COUNTRY_CODE "!@streq US"
```

Test the configuration.

```
sudo nginx -t
```

Validate the nginx test is okay.

```
sudo nginx -s reload
```

Validate you're blocking countries outside the US