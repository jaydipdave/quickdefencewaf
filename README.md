# QuickDefence - Web Application Firewall [README]

## What is QuickDefence - WAF?

* It is an easy to setup Web Application Firewall without doing major changes in your server architecture
* You just need to setup a Reverse Proxy within your server or between your server and the internet
* Nginx is full featured reverse proxy freely available on the internet. Nginx can solve load balancing problem, website performance related issue, old server vulnerability related issues etc
* It has very easy to understand rule writing, very good for quick virtual web application vulnerability patching
* It can easily be deployed in to a hardware or a virtual appliance

## Why QuickDefence ? [Features]

* mod_security is a very good WAF, it is very hard for any open source WAF to even reach at that level. The only issue with mod_security is, it is very complex in configuration writing rules. Even for programmers it is hard to understand sometimes. The scoring system of mod_security is also difficult to understand. No body is going to entirely utilize mod_security and its features.
* QuickDefence is actually targeted for instant basic protection from critical threats. For now, at least someone can easily set it up for the first level of defence.
* QuickDefence is based on Nginx, so it will boost the website performance drastically.
* Nginx can easily provide efficient load balancing
* Lua is a very fast scripting language, so it wont affect the performance of the website.
* Honeypots can also be configured to misguide attackers.
* Very good response data and response header filtration. (can be used for Error suppression)
* Block a triggered rule request for certain seconds and then redirect the attacker to some other page. This will block any scanner scanning your website.
* Score based rule action. If sum of scores for all the matches become >= 100. The request is blocked.
Tons of things are yet to be developed.

## YET TODO

* RULE WRITING: I didn't get time to write rules, you might want to come up with generic rules
* EXPANSION OF VULNERABILITY COVERAGE
* REGRESSION TESTING AND STRESS TESTING
* WEB-UI TO MANAGE NGINX AND RULES REMOTELY
* RULE WRITING CAPABILITY FOR FILE UPLOADS
* Build Virtual Appliance
* ANALYTICS: A BASIC VERSION OF GOOGLE ANALYTICS.
* Tokenizer : CSRF Protection
* Profiling Mode: Whitelisting approach instead of Blacklisting
* SAMPLE RULES
	
## SAMPLE RULES

```
RULE: ALLOWED_METHODS "GET, POST"
RULE: LOAD_PATTERNS "SQL_PATTERNS=/WAF/Rules/sql_patterns.txt"
RULE: LOAD_PATTERNS "XSS_PATTERNS=/WAF/Rules/xss_patterns.txt"

RULE: SQL_INJECTION "/"
	MATCHES: HEADERS,POST_DATA,QUERY_STRING,URI,COOKIES<!__utm>
	PATTERN: "<SQL_PATTERNS>"
		SCORE: 50
	MATCHES: HEADERS,POST_DATA,QUERY_STRING,URI,COOKIES,HEADER_NAMES,QUERY_FIELDS,POST_FIELDS,POST_BODY,COOKIE_NAMES,METHOD
	PATTERN: "select.*from"
		SCORE: 50	
```

## INSTALLATION

As such there is no installation required. You just need to configure your Nginx, having HttpLuaModule module installed.

### Nginx & HttpLuaModule Installation
You can install [Nginx](http://wiki.nginx.org/Install) with [HttpLuaModule](http://wiki.nginx.org/HttpLuaModule) module manually

or

I would suggest to install [openresty](http://openresty.org/) package, which includes Nginx and Lua.

### Nginx Configuration
* Copy waf.lua file into lualib folder (for me it is: /usr/local/openresty/lualib/waf.lua)
* Edit /usr/local/openresty/nginx/conf/nginx.conf file to configure your web server
* Change the configuration as per below (This is a part of the file which needs to be changed)

```
init_by_lua 'waf = require "waf"; waf.load_rules()';
	server {
		listen       80;
		server_name  localhost;

		default_type 'text/html';

		location / {
			#content_by_lua 'ngx.say(rules)';

			access_by_lua 'waf.fetch_request();waf.get_cookies();waf.protect()';
			proxy_pass http://localhost:8080;
			header_filter_by_lua_file '/usr/local/openresty/nginx/conf/header_filter.lua';
			body_filter_by_lua_file '/usr/local/openresty/nginx/conf/body_filter.lua';
		}
```
* As shown in above code, you need to configure paths for the header_filer.lua and body_filter.lua file. This is basically used for filtering webserver responses.
* Change the proxy_pass parameter to your own website to make it working. You can also redirect it to public facing website to test the waf. (like http://demo.testfire.net, http://webscantest.com, http://crackme.cenzic.com)
* Play around with /mnt/hgfs/myscanner/Extras/WAF/Rules/rules.txt rules file and virtually patch all the vulnerabilities
		
## Motive
	
* An easy to configure and use Web Application Firewall, available to all kind of public and secure websites from common attacks.
	
## Got a Question?
	
* jaydipdave@gmail.com
	
		



