<p align="center"><img src="https://hosting.kiniditech.com/the-helper-php.png" width="200" alt="The Helper PHP"></p>

# The Helper PHP

The Helper PHP - a lot of PHP helper functions that are ready to help in your project

## Function List

-  validate_input (Validating input string - prevent SQL injection & XSS)
-  validate_input_url (Validating input URL - prevent SQL injection & XSS)
-  validate_input_word (Validating input word (usually: username) - prevent SQL injection & XSS)
-  validate_input_email (Validate input email)
-  validate_input_text (Allow all characters within "FILTER_SANITIZE_MAGIC_QUOTES")
-  validate_phone (For validate phone, support generate format using phone code)
-  hashing_this (Hashing string using declared algorithm)
-  generate_parent_child_data (Generate parent-child data from array object)
-  convert_datepicker (Convert date format, usually used for bootstrap datepicker from "dd/mm/yyyy" to "yyyy-mm-dd")
-  get_end_days_of_month (Get end days of the month)
-  validate_recaptcha (Validate reCAPTCHA version 2)
- random_string (Generate random string)
- generate_slug (Generate slug for SEF (Search Engine Friendly) URL)
- set_pagination (Set pagination using total data)
- generate_token (Generate token based on string (safe for URL))
- validate_token (Validate token based on string that generated by function "generate_token()")
- read_more (Generate READ MORE paragraph for long text)
- time_ago (Used to format date with "*** time ago" - sample: "3 hours ago" & support multilanguage)
- get_diff_dates (Used to get the difference in days from the 2 input dates)
- check_url (Used to check validity the URL)
- is_webview (Used to check whether opened via webview (Android & iOS) or not)
- get_url (Get current full URL )
- check_remote_file (Check whether the url file is valid)
- get_family_name (Get family name (firstname & lastname))

## How-to-Use

You can include this PHP file into your PHP project
```
include __DIR__ . "/TheHelper.php";
require_once __DIR__ . "/TheHelper.php";
```

Then you can use the function in "The Helper PHP"
```
$name = TheHelper::validate_input_text($_POST['name']);
```

## Contributing

Thank you for considering contributing to the "The Helper PHP".

## Bugs, Improvements & Security Vulnerabilities

If you discover a bug or security vulnerability within "The Helper PHP", please send an email to Vicky Budiman at [vicky@kiniditech.com](mailto:vicky@kiniditech.com). All requests will be addressed promptly.

## Issues

If you come across any issue/bug please [report them here](https://github.com/vickzkater/the-helper-php/issues).

## License

The Helper PHP is open-sourced software built by KINIDI Tech and contributors and licensed under the [MIT license](http://opensource.org/licenses/MIT).

## Credits

- Vicky Budiman (https://github.com/vickzkater)

<p align="center">Brought to you by</p>
<p align="center"><img src="https://hosting.kiniditech.com/kiniditech_logo.png" width="200" alt="KINDI Tech"></p>
<p align="center">KINIDI Tech</p>
