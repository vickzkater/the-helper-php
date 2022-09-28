<?php

/**
 * The Helper PHP - a lot of PHP helper functions that are ready to help in your project
 * Version: 1.0.2 (2022-09-28)
 *
 * Copyright (c) KINIDI Tech and other contributors
 * Released under the MIT license.
 * For more information, see https://kiniditech.com/ or https://github.com/vickzkater
 * 
 * https://github.com/vickzkater/the-helper-php
 */

class TheHelper
{
    /**
     * Validating input string - prevent SQL injection & XSS
     * 
     * @param String $string required
     * 
     * @return String (valid string)
     */
    public static function validate_input($string)
    {
        if ($string == '' || !$string) {
            return null;
        }

        $string = filter_var($string, FILTER_SANITIZE_STRING);

        // only support for these chars
        $string = preg_replace("/[^a-z 0-9-_'.]+/i", "", $string);

        // for sanitize (">) ('>)
        if ($string == 34 || $string == 39) {
            return null;
        }

        return $string;
    }

    /**
     * Validating input URL - prevent SQL injection & XSS
     * 
     * @param String $string required
     * 
     * @return String (valid URL)
     */
    public static function validate_input_url($string)
    {
        if ($string == '' || !$string) {
            return null;
        }

        $string = filter_var($string, FILTER_VALIDATE_URL);

        // for sanitize (">) ('>)
        if ($string == 34 || $string == 39) {
            return null;
        }

        return $string;
    }

    /**
     * Validating input word (usually: username) - prevent SQL injection & XSS
     * 
     * @param String $string required
     * 
     * @return String (valid string without space)
     */
    public static function validate_input_word($string)
    {
        if ($string == '' || !$string) {
            return null;
        }

        $string = filter_var($string, FILTER_SANITIZE_STRING);

        // only support these chars
        $string = preg_replace("/[^a-z0-9_.]+/i", "", $string);

        // for sanitize (">) ('>)
        if ($string == 34 || $string == 39) {
            return null;
        }

        return $string;
    }

    /**
     * Validate input email
     * 
     * @param String $string required
     * 
     * @return String (valid email)
     */
    public static function validate_input_email($string)
    {
        // remove spaces & convert to lowercase
        $string = str_replace(' ', '', strtolower($string));

        $val = filter_var($string, FILTER_VALIDATE_EMAIL);
        if ($val) {
            return $string;
        }
        return null;
    }

    /**
     * Allow all characters within "FILTER_SANITIZE_ADD_SLASHES"
     * If ($no_backslash == false) and it contains symbols: single quote (') and double quote (") 
     * Then it will add symbol backslash (\) before those symbols
     * 
     * @param String $string required
     * @param Boolean $htmlspecialchars optional
     * @param Boolean $no_backslash optional
     * 
     * @return String
     */
    public static function validate_input_text($string, $htmlspecialchars = false, $no_backslash = true)
    {
        if ($string == '' || !$string) {
            return null;
        }
        if (version_compare(PHP_VERSION, '7.4.0') >= 0) {
            $val = filter_var($string, FILTER_SANITIZE_ADD_SLASHES);
        } else {
            $val = filter_var($string, FILTER_SANITIZE_MAGIC_QUOTES);
        }
        if ($no_backslash) {
            $val = stripslashes($val);
        }
        if ($htmlspecialchars) {
            $val = htmlspecialchars($val);
        }
        return $val;
    }

    /**
     * For validate phone, support generate format using phone code
     * *Example: 
     * validate_phone('081234567890', '62', '0') > result: 6281234567890
     * validate_phone('6281234567890', '62', '0') > result: 6281234567890
     * validate_phone('081234567890', '62') > result: 62081234567890
     * validate_phone('81234567890', '62') > result: 6281234567890
     * 
     * @param String $phone required (number enclosed in quotation marks)
     * @param String $phone_code optional
     * @param Number $start_using optional
     * 
     * @return Array [status, message, data]
     */
    public static function validate_phone($phone, $phone_code = null, $start_using = '')
    {
        $phone = TheHelper::validate_input($phone);

        // sanitize phone number: length(10-18 chars)
        if (strlen($phone) < 10 || strlen($phone) > 18) {
            // FAILED
            return [
                'status' => false,
                'message' => 'The length of a phone number is around 10-14 digits',
                'data' => ''
            ];
        }

        if ($phone_code) {
            // check if phone code is used on phone number
            if (substr($phone, 0, strlen($phone_code)) == $phone_code) {
                // SUCCESS
                return [
                    'status' => true,
                    'message' => 'Successfully validate phone number',
                    'data' => $phone
                ];
            } else {
                // need to replace it, but must set value "start_using"
                if ($start_using != '') {
                    // phone number start using value "start_using"
                    if (substr($phone, 0, strlen($start_using)) == $start_using) {
                        // replace it
                        $phone = $phone_code . substr($phone, strlen($start_using));
                    } else {
                        // add the phone code
                        $phone = $phone_code . $phone;
                    }

                    // SUCCESS
                    return [
                        'status' => true,
                        'message' => 'Successfully validate phone number',
                        'data' => $phone
                    ];
                } else {
                    // SUCCESS - just add "phone_code" as prefix
                    return [
                        'status' => true,
                        'message' => 'Successfully validate phone number',
                        'data' => $phone_code . $phone
                    ];
                }
            }
        }

        // SUCCESS - return the value as is
        return [
            'status' => true,
            'message' => 'Successfully validate phone number',
            'data' => $phone
        ];
    }

    /**
     * Hashing string using declared algorithm
     * 
     * @param String $string required
     * 
     * @return String
     */
    public static function hashing_this($string)
    {
        // return substr(md5($string), 5, 25);
        // return bcrypt(sha1(str_replace(" ", "", $string)));

        // Ref: https://www.php.net/manual/en/function.password-hash.php
        return password_hash($string, PASSWORD_DEFAULT);
    }

    /**
     * 2019-10-26
     * 
     * Generate parent-child data in array object value from array object
     * 
     * @param Array $array_object required | array objects
     * @param String $parent required | for set parent index
     * @param Array $params_child optional | for set what data that you want to save in children array | sample: ['id', 'name', 'description']
     * 
     * @return Array
     * 
     * *Sample:
     *  > before
     *  array:3 [
     * 		0 => { "category": "Hardware", "name": "CPU" }
     * 		1 => { "category": "Hardware", "name": "Monitor" }
     * 		2 => { "category": "Software", "name": "OS" }
     * 	]
     * 
     * 	> after
     * 	array:2 [
     * 		"Hardware" => array:2 [
     * 			0 => { "name": "CPU" }
     * 			1 => { "name": "Monitor" }
     * 		] 
     * 		"Software" => array:1 [
     * 			0 => { "name": "OS" }
     * 		] 
     * 	]
     */
    public static function generate_parent_child_data($array_object, $parent, $params_child = null)
    {
        if ($array_object && count($array_object) > 0) {
            $parents = [];
            $child = [];
            $tmp = [];

            foreach ($array_object as $value) {
                if (!in_array($value->$parent, $parents)) {
                    $parents[] = $value->$parent;

                    if (count($tmp) > 0) {
                        $child[] = $tmp;
                    }
                    $tmp = [];
                }

                $obj = new \stdClass();

                if ($params_child) {
                    // set children data by params
                    foreach ($params_child as $param) {
                        if (isset($value->$param)) {
                            $obj->$param = $value->$param;
                        } else {
                            $obj->$param = '';
                        }
                    }
                } else {
                    // default for set children data
                    $obj->id = $value->id;
                }

                $tmp[] = $obj;
            }

            // save the last child data
            $child[] = $tmp;

            $array = [];
            for ($i = 0; $i < count($child); $i++) {
                $array[$parents[$i]] = $child[$i];
            }

            return $array;
        } else {
            // return empty array
            return array();
        }
    }

    /**
     * Generate parent-child data in array list value from array object
     */
    public static function generate_parent_child_data_array($array_object, $parent, $params_child = null)
    {
        if ($array_object && count($array_object) > 0) {
            $parents = [];
            $child = [];
            $tmp = [];

            foreach ($array_object as $value) {
                if (!in_array($value[$parent], $parents)) {
                    $parents[] = $value[$parent];

                    if (count($tmp) > 0) {
                        $child[] = $tmp;
                    }
                    $tmp = [];
                }

                $obj = [];

                if ($params_child) {
                    // set children data by params
                    foreach ($params_child as $param) {
                        if (isset($value[$param])) {
                            $obj[$param] = $value[$param];
                        } else {
                            $obj[$param] = '';
                        }
                    }
                } else {
                    // default for set children data
                    $obj['id'] = $value['id'];
                }

                $tmp[] = $obj;
            }

            // save the last child data
            $child[] = $tmp;

            $array = [];
            for ($i = 0; $i < count($child); $i++) {
                $array[$parents[$i]] = $child[$i];
            }

            return $array;
        } else {
            // return empty array
            return array();
        }
    }

    /**
     * Convert date format, usually used for bootstrap datepicker
     * From "dd/mm/yyyy" to "yyyy-mm-dd"
     * 
     * @param String $inputdate required | date (31/01/2020)
     * @param String $delimiter optional
     * @param String $glue optional
     * @param Integer $order optional | 31/01/2020 >> 31=0; 01=1; 2020=2; - so you can set order using the index, sample: 210 (2020/01/31)
     * 
     * @return String
     */
    public static function convert_datepicker($inputdate, $delimiter = '/', $glue = '-', $order = 210)
    {
        if (!empty($inputdate)) {
            $date_arr = explode($delimiter, $inputdate);
            if (count($date_arr) < 3) {
                return 'INVALID DATE FORMAT';
            }
            $order_arr = str_split($order);
            if (count($order_arr) < 3) {
                return 'INVALID DATE ORDER';
            }
            return $date_arr[$order_arr[0]] . $glue . $date_arr[$order_arr[1]] . $glue . $date_arr[$order_arr[2]];
        }
        return 'NO INPUT DATE';
    }

    /**
     * Get end days of the month
     * 
     * @param Integer $month optional | Jan=1, Dec=12
     * @param Integer $year optional | 2019, 2020, etc
     * 
     * @return Integer
     */
    public static function get_end_days_of_month($month = null, $year = null)
    {
        if (empty($month)) {
            $month = date('n');
        }

        if (empty($year)) {
            $year = date('Y');
        }

        $mon31days = [1, 3, 5, 7, 8, 10, 12];
        $mon30days = [4, 6, 9, 11];
        if (in_array($month, $mon31days)) {
            $end_date = 31;
        } elseif (in_array($month, $mon30days)) {
            $end_date = 30;
        } elseif ($year % 4 == 0) {
            $end_date = 29;
        } else {
            $end_date = 28;
        }

        return $end_date;
    }

    /**
     * Validate reCAPTCHA version 2
     * 
     * @param String $g_recaptcha_response required | post param from form
     * @param String $secret_key required | reCAPTCHA Secret Key
     * 
     * @return Boolean
     */
    public static function validate_recaptcha($g_recaptcha_response, $secret_key)
    {
        $fields = array(
            'secret'    =>  $secret_key,
            'response'  =>  $g_recaptcha_response,
            'remoteip'  =>  $_SERVER['REMOTE_ADDR']
        );
        $ch = curl_init("https://www.google.com/recaptcha/api/siteverify");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($fields));
        $response = json_decode(curl_exec($ch), TRUE);

        // validation reCAPTCHA is failed
        if ($response['success'] == false) {
            return false;
        }

        return true;
    }

    /**
     * Generate random string
     * 
     * @param Integer $strength optional
     * 
     * @return String
     */
    public static function random_string($strength = 16)
    {
        $permitted_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $input_length = strlen($permitted_chars);
        $random_string = '';
        for ($i = 0; $i < $strength; $i++) {
            $random_character = $permitted_chars[mt_rand(0, $input_length - 1)];
            $random_string .= $random_character;
        }

        return $random_string;
    }

    /**
     * Generate slug for SEF (Search Engine Friendly) URL
     * 
     * @param String $string required
     * @param Boolean $ideal optional
     * 
     * @return String
     */
    public static function generate_slug($string, $ideal = true)
    {
        $table = array(
            'Š' => 'S', 'š' => 's', 'Đ' => 'Dj', 'đ' => 'dj', 'Ž' => 'Z', 'ž' => 'z', 'Č' => 'C', 'č' => 'c', 'Ć' => 'C', 'ć' => 'c',
            'À' => 'A', 'Á' => 'A', 'Â' => 'A', 'Ã' => 'A', 'Ä' => 'A', 'Å' => 'A', 'Æ' => 'A', 'Ç' => 'C', 'È' => 'E', 'É' => 'E',
            'Ê' => 'E', 'Ë' => 'E', 'Ì' => 'I', 'Í' => 'I', 'Î' => 'I', 'Ï' => 'I', 'Ñ' => 'N', 'Ò' => 'O', 'Ó' => 'O', 'Ô' => 'O',
            'Õ' => 'O', 'Ö' => 'O', 'Ø' => 'O', 'Ù' => 'U', 'Ú' => 'U', 'Û' => 'U', 'Ü' => 'U', 'Ý' => 'Y', 'Þ' => 'B', 'ß' => 'Ss',
            'à' => 'a', 'á' => 'a', 'â' => 'a', 'ã' => 'a', 'ä' => 'a', 'å' => 'a', 'æ' => 'a', 'ç' => 'c', 'è' => 'e', 'é' => 'e',
            'ê' => 'e', 'ë' => 'e', 'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i', 'ð' => 'o', 'ñ' => 'n', 'ò' => 'o', 'ó' => 'o',
            'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ø' => 'o', 'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ý' => 'y', 'ý' => 'y', 'þ' => 'b',
            'ÿ' => 'y', 'Ŕ' => 'R', 'ŕ' => 'r',
        );

        $formatted_string = strtr($string, $table);

        $formatted_string = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $formatted_string)));

        // ideal of slug is about 80-100 chars
        if ($ideal) {
            $formatted_string = substr($formatted_string, 0, 98);
        }

        if (substr($formatted_string, -1) == '-') {
            // REMOVE THE LAST STRIP '-'
            $formatted_string = substr($formatted_string, 0, strlen($formatted_string) - 1);
        }

        return $formatted_string;
    }

    /**
     * Set pagination using total data
     * 
     * @param integer $totaldata required
     * @param integer $page optional | index page, start from 1 
     * @param integer $perpage optional | quota items per page
     * @param integer $maximal optional
     * 
     * @return Object
     */
    public static function set_pagination($totaldata, $page = 1, $perpage = 30, $maximal = 100)
    {
        if ($perpage > $maximal) {
            $perpage = $maximal;
        }

        $obj = new \stdClass();
        if ($perpage > 0) {
            $obj->pages = ceil($totaldata / $perpage); // total pages of data
            $obj->startfrom = ($page - 1) * $perpage;
        } else {
            $obj->pages = 1;
            $obj->startfrom = 0;
        }
        return $obj;
    }

    /**
     * Generate token based on string (safe for URL)
     * 
     * @param String $string required
     * @param Integer $salt_chars optional
     * 
     * @return String
     */
    public static function generate_token($string, $salt_chars = 15)
    {
        return urlencode(TheHelper::random_string($salt_chars) . base64_encode($string));
    }

    /**
     * Validate token based on string that generated by function "generate_token($string)"
     * 
     * @param String $token required
     * @param Integer $salt_chars optional
     * 
     * @return String
     */
    public static function validate_token($token, $salt_chars = 15)
    {
        return base64_decode(substr(urldecode($token), $salt_chars));
    }

    /**
     * Generate READ MORE paragraph for long text
     * 
     * @param String $text required
     * @param Integer $total_chars optional
     * 
     * @return String
     */
    public static function read_more($text, $total_chars = 50)
    {
        if (!$text) {
            return null;
        }
        if (strlen($text) > $total_chars) {
            return mb_strcut($text, 0, $total_chars) . "...";
        }
        return $text;
    }

    /**
     * Used to format date with "*** time ago" - sample: "3 hours ago" & support multilanguage
     * 
     * @param String $time required
     * @param String $tense_ago optional
     * @param Array $periods optional
     * 
     * @return String
     */
    public static function time_ago($time, $tense_ago = 'ago', $periods = array("second", "minute", "hour", "day", "week", "month", "year", "decade"))
    {
        $lengths = array("60", "60", "24", "7", "4.35", "12", "10");

        $now = time();

        $difference = $now - $time;

        for ($j = 0; $difference >= $lengths[$j] && $j < count($lengths) - 1; $j++) {
            $difference /= $lengths[$j];
        }

        $difference = round($difference);

        if ($tense_ago == 'ago' && $difference != 1) {
            $periods[$j] .= "s";
        }

        return "$difference $periods[$j] $tense_ago";
    }

    /**
     * Used to format date with "*** time more" - sample: "3 hours more" & support multilanguage
     * 
     * @param String $time required
     * @param String $tense_more optional
     * @param Array $periods optional
     * 
     * @return String
     */
    public static function time_more($time, $tense_more = 'more', $periods = array("second", "minute", "hour", "day", "week", "month", "year", "decade"))
    {
        $lengths = array("60", "60", "24", "7", "4.35", "12", "10");

        $now = time();

        $difference = $time - $now;

        if ($difference <= 0) {
            return '0';
        }

        for ($j = 0; $difference >= $lengths[$j] && $j < count($lengths) - 1; $j++) {
            $difference /= $lengths[$j];
        }

        $difference = round($difference);

        if ($tense_more == 'more' && $difference != 1) {
            $periods[$j] .= "s";
        }

        return "$difference $periods[$j] $tense_more";
    }

    /**
     * Used to get the difference in days from the 2 input dates
     * 
     * @param String $date_start required | date with format Y-m-d
     * @param String $date_end optional
     * @param String $date_format optional
     * 
     * @return Integer
     */
    public static function get_diff_dates($date_start, $date_end = null, $date_format = "%a")
    {
        if (empty($date_end)) {
            $date_end = date('Y-m-d'); // NOW
        }

        $date1 = date_create($date_start);
        $date2 = date_create($date_end);
        $diff = date_diff($date1, $date2);
        return (int) $diff->format($date_format);
    }

    public static function get_date_diff($date1, $date2 = null, $diff_type = 'days', $date_format = null)
    {
        if (empty($date2)) {
            $date2 = date('Y-m-d'); // NOW
        }

        $datetime1 = date_create($date1);
        $datetime2 = date_create($date2);

        $diff = date_diff($datetime1, $datetime2);

        if (empty($date_format)) {
            switch ($diff_type) {
                case 'full':
                    $date_format = '%y Year %m Month %d Day %h Hour %i Minute %s Seconds';
                    break;

                case 'year':
                    $date_format = '%y';
                    break;

                case 'month':
                    $date_format = '%m';
                    break;

                case 'day':
                    $date_format = '%d';
                    break;

                case 'hour':
                    $date_format = '%h';
                    break;

                case 'minute':
                    $date_format = '%i';
                    break;

                case 'second':
                    $date_format = '%s';
                    break;

                default:
                    # days
                    $date_format = '%a';
                    break;
            }
        }

        return $diff->format($date_format);
    }

    public static function second_diff($datetime1, $datetime2 = null)
    {
        if (empty($datetime2)) {
            $timestamp2 = time(); // NOW
        } else {
            $timestamp2 = strtotime($datetime2);
        }

        $timestamp1 = strtotime($datetime1);
        return ($timestamp2 - $timestamp1);
        // return [
        //     $datetime1, 
        //     $datetime2,
        //     ($timestamp2 - $timestamp1)
        // ];
    }

    /**
     * Used to check validity the URL
     * 
     * @param String $url required
     * 
     * @return Boolean
     */
    public static function check_url($url)
    {
        $headers = get_headers($url);
        return stripos($headers[0], "200 OK") ? true : false;
    }

    /**
     * Used to check whether opened via webview (Android & iOS) or not
     * 
     * @param String $android_package_name optional
     * 
     * @return Boolean
     */
    public static function is_webview($android_package_name = "com.company.app")
    {
        $is_webview = false;

        // For iOS
        if ((strpos($_SERVER['HTTP_USER_AGENT'], 'Mobile/') !== false) && (strpos($_SERVER['HTTP_USER_AGENT'], 'Safari/') == false)) {
            $is_webview = true;
        }

        // For Android
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] == $android_package_name) {
            $is_webview = true;
        }

        return $is_webview;
    }

    /**
     * Get current full URL 
     * 
     * @return String
     */
    public static function get_url()
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    }

    /**
     * Check whether the url file is valid 
     * 
     * @param String $url required
     * 
     * @return Boolean
     */
    public static function check_remote_file($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        // don't download content
        curl_setopt($ch, CURLOPT_NOBODY, 1);
        curl_setopt($ch, CURLOPT_FAILONERROR, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $result = curl_exec($ch);
        curl_close($ch);
        if ($result !== FALSE) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Get family name (firstname & lastname)
     * 
     * @param String $fullname required
     * @param String $default_lastname optional
     * 
     * @return Object
     */
    public static function get_family_name($fullname, $default_lastname = null)
    {
        $arr_names = explode(' ', $fullname);
        if (count($arr_names) == 1) {
            $lastname = $arr_names[0];
            if ($default_lastname) {
                $lastname = $default_lastname;
            }
            $firstname = $arr_names[0];
        } else {
            $lastname = $arr_names[(count($arr_names) - 1)];
            array_pop($arr_names);
            $firstname = implode(' ', $arr_names);
        }

        $obj = new \stdClass();
        $obj->firstname = $firstname;
        $obj->lastname = $lastname;

        return $obj;
    }

    /**
     * For check if a string contains a specific word
     * @param String $needle required
     * @param String $haystack required
     * 
     * @return Boolean
     */
    public static function is_contains($needle, $haystack)
    {
        if (empty($needle)) {
            return false;
        }
        if (stripos($haystack, $needle) !== false) {
            return true;
        }
        return false;
    }

    /**
     * Generate random unique string
     * 
     * @return String
     */
    public static function unique_string()
    {
        return md5(uniqid());
    }

    /**
     * Generate random image
     * @param Integer $width optional
     * @param Integer $height optional
     * 
     * @return String
     */
    public static function random_image($width = 800, $height = 500)
    {
        return 'https://picsum.photos/' . $width . '/' . $height . '?random=' . rand();
    }

    /**
     * Generate zero number
     * @param Integer $input_number required
     * @param Integer $how_long optional
     * 
     * @return String
     */
    public static function generate_zero_number($input_number, $how_long = 4)
    {
        if (!is_numeric($input_number) || !is_numeric($how_long)) {
            return '0';
        }

        if (strlen($input_number) >= (int) $how_long) {
            return $input_number;
        } else {
            return str_pad($input_number, $how_long, '0', STR_PAD_LEFT);
        }
    }

    /**
     * Generate token auth
     * @param Integer $how_long optional
     * 
     * @return String
     */
    public static function generate_token_auth($how_long = 50)
    {
        $how_long = (int) $how_long;
        if (!$how_long) {
            $how_long = 50;
        }

        $token = TheHelper::unique_string() . TheHelper::unique_string();

        if (strlen($token) > $how_long) {
            return substr($token, 0, $how_long);
        } else {
            return $token;
        }
    }

    /**
     * Convert timestamp from server timezone to specific timezone
     * *Example
     * Server Timezone is UTC, then you want convert to Asia/Jakarta (GMT+7)
     * From "2021-11-21 10:00:00" will be converted to "2021-11-21 17:00:00"
     * 
     * @param String $timestamp required (sample: 2021-11-21 10:00:00)
     * @param String $format optional (sample: Y-m-d H:i:s)
     * @param String $timezone optional (sample: Asia/Jakarta)
     * 
     * @return String
     */
    public static function convert_timestamp($timestamp, $format = 'Y-m-d H:i:s', $timezone = 'UTC')
    {
        $server_timezone = date_default_timezone_get();
        $date = new \DateTime($timestamp, new \DateTimeZone($server_timezone));
        $date->setTimezone(new \DateTimeZone($timezone));

        return $date->format($format);
    }

    /**
     * Convert timestamp from one timezone to another timezone
     * *Example
     * From UTC timezone, then you want convert it to Asia/Jakarta (GMT+7) timezone
     * From "2021-11-21 10:00:00" will be converted to "2021-11-21 17:00:00"
     * 
     * @param String $timestamp required (sample: 2021-11-21 10:00:00)
     * @param String $format optional (sample: Y-m-d H:i:s)
     * @param String $timezone_from optional (sample: UTC)
     * @param String $timezone_to optional (sample: Asia/Jakarta)
     * 
     * @return String
     */
    public static function convert_timestamp_from_to($timestamp, $format = 'Y-m-d H:i:s', $timezone_from = 'UTC', $timezone_to = 'Asia/Jakarta')
    {
        $date = new \DateTime($timestamp, new \DateTimeZone($timezone_from));
        $date->setTimezone(new \DateTimeZone($timezone_to));

        return $date->format($format);
    }

    public static function currency_format($nominal, $decimals = 0, $decimal_separator = '.', $thousands_separator = ',', $prefix = null, $suffix = null)
    {
        $result = $prefix;
        $result .= number_format($nominal, $decimals, $decimal_separator, $thousands_separator);
        $result .= $suffix;

        return $result;
    }

    /**
     * Generate random code
     * 
     * @return String
     */
    public static function random_code($length = null, $use_only_capital_letters = false)
    {
        $code = md5(uniqid());

        $length = (int) $length;
        if ($length > 0) {
            while (strlen($code) < $length) {
                $code .= md5(uniqid());
            }

            $code = substr($code, 0, $length);
        }

        if ($use_only_capital_letters) {
            $code = strtoupper($code);
        }

        return $code;
    }

    public static function plural($wording, $amount)
    {
        $wording = strtolower($wording);
        if ($amount > 1) {
            switch (substr($wording, -2, 1)) {
                case 'f':
                    return substr($wording, 0, -2) . 'v' . substr($wording, -1) . 's'; // knife >> knives
                    break;
            }

            switch (substr($wording, -1)) {
                case 's':
                    return $wording . 'es'; // mess >> messes
                    break;

                case 'z':
                    return $wording . 'es'; // waltz >> waltzes
                    break;

                case 'f':
                    return substr($wording, 0, -1) . 'ves'; // leaf >> leaves
                    break;

                case 'y':
                    if (in_array(substr($wording, -2, 1), ['a', 'i', 'u', 'e', 'o'])) {
                        return $wording . 's'; // day >> days
                    }
                    return substr($wording, 0, -1) . 'ies'; // category >> categories
                    break;

                case 'o':
                    if (in_array(substr($wording, -2, 1), ['a', 'i', 'u', 'e', 'o'])) {
                        return $wording . 's'; // video >> videos
                    }
                    return $wording . 'es'; // potato >> potatoes
                    break;

                case 'h':
                    if (in_array(substr($wording, -2, 1), ['a', 'i', 'u', 'e', 'o'])) {
                        return $wording . 's'; // rupiah >> rupiahs
                    }
                    return $wording . 'es'; // brush >> brushes
                    break;

                default:
                    return $wording . 's'; // dog >> dogs
                    break;
            }
        }
        return $wording;
    }

    public static function convert_bytes($amount_bytes)
    {
        $threshold = 1024;

        $units = [
            'Bytes',
            'KB',
            'MB',
            'GB',
            'TB'
        ];

        if ($amount_bytes < $threshold) {
            return $amount_bytes . ' ' . $units[0];
        } else {
            $level = 0;
            $threshold_level = 1;
            do {
                $threshold_now = pow($threshold, $threshold_level);

                $divided = $amount_bytes / $threshold_now;
                
                $result = number_format($divided, 1);
                $explode_result = explode('.', $result);

                if ($explode_result[1] == '0') {
                    $result = $explode_result[0];
                }
                
                $level++;
                $threshold_level++;
            } while ($divided > $threshold);

            // dd($divided, number_format($divided, 1), $explode_result, $result, $units[$level]);
            return $result . ' ' . $units[$level];
        }
    }
}
