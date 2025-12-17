# CVE-2025-58449

#### Summary

In Maho 25.7.0, an authenticated staff user with access to the `Dashboard` and `Catalog\Manage Products` permissions can create a custom option on a listing with a file input field. By allowing file uploads with a `.php` extension, the user can use the filed to upload malicious PHP files, gaining remote code execution

#### Details

An  user with the `Dashboard` and `Catalog\Manage Products` permissions can abuse the product custom options feature to bypass the application’s file upload restrictions.

When creating a product custom option of type file upload, the user is allowed to define their own extension whitelist. This bypasses the application’s normal enforced whitelist and permits disallowed extensions, including `.php`.

The file uploaded by the custom option is then written to a predictable location:
```
/public/media/custom_options/<first char of filename>/<second char of filename>/<md5 of file contents>.php
```
Because this path is directly accessible under the application’s webroot, an attacker can then request the uploaded file via HTTP, causing the server to execute the PHP payload.


#### PoC
1. Sign in to the `/admin` dashboard as a staff user. Ensure the user's role has access to the `Dashboard` and `Catalog\Manage Products` permissions.

2. Navigate to a product catalog listing, for example by clicking on a product linked within the `Most Viewed Products` tab on the dashboard.
![maho-1](/assets/maho/maho-1.png)

3. Navigate to the "Custom Options" tab on the product, and create a custom option with a file upload field. Add `.php` as an allowed extension to the file upload configuration. Save the configuration after making the changes.

![maho-2](/assets/maho/maho-2.png)

4. In a private window, navigate to the customer facing page for the product, and upload a reverse shell PHP file through the newly configured option. Then click "Add to cart" to complete the upload.

![maho-3](/assets/maho/maho-3.png)


5. Calculate the location of the uploaded file on the web server as 
```
/public/media/custom_options/<first char of filename>/<second char of filename>/<md5 of file contents>.php
```
6. Navigate to the above path directly to execute the file contents and trigger the reverse shell.

![maho-4](/assets/maho/maho-4.png)

#### Impact
This vulnerability allows remote code execution (RCE) on the server. It requires only the `Catalog\Manage` Products permission, and does not need full administrative access. By leveraging the custom option upload feature, an attacker can bypass the application’s normal file upload protections and execute arbitrary PHP code within the webroot.

#### Timeline

- August 28 2025: Initial disclosure to MahoCommerce
- September 8 2025: CVE-2025-58449 assigned
- September 10 2025: Public disclosure and release of version 25.9.0
