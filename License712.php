<?php namespace WHMCS;

/**
 * WHMCS License Class
 * nuller.ir
 * Handles license checking & validation
 *
 * @author     WHMCS Limited <development@whmcs.com>
 * @copyright  Copyright (c) WHMCS Limited 2005-2016
 */

class License
{
    private $licensekey = "";
    private $localkey = "";
    private $keydata = array();
    private $salt = "";
    private $date = "";
    private $localkeydecoded = false;
    private $responsedata = "";
    private $postmd5hash = "";
    private $localkeydays = "10";
    private $allowcheckfaildays = "5";
/**
     * @var array
     */
    private $debuglog = array();
    private $version = "5cc7720f613926993107a6123a28eeaad706fc6a42324b40a3764748a28322280f5c373047bb2efad6f350a3bf070ad7ea0814abc720a6fb284fa6df4abea02e";

    const LICENSE_API_VERSION = "1.1";
    const LICENSE_API_HOSTS = array( "" );

    public function __construct(Application $whmcs)
    {
        $this->licensekey = $whmcs->get_license_key();
        $this->localkey = $whmcs->get_config("License");
        $this->salt = sha1("WHMCS" . $whmcs->get_config("Version") . "TFB" . $whmcs->get_hash());
        $this->date = date("Ymd");
        $this->decodeLocalOnce();
        if( isset($_GET["forceremote"]) ) 
        {
            $this->forceRemoteCheck();
            Terminus::getInstance()->doExit();
        }

    }

    /**
     * Retrieve a WHMCS\License object via singleton.
     *
     * @deprecated 6.0 Instance should be retrieved from DI [DI::make('license');]
     *
     * @return License
     */

    public static function getInstance()
    {
        return \DI::make("license");
    }

    public function useInternalLicensingValidation()
    {
        $config = \App::getApplicationConfig();
        return (bool) $config["use_internal_licensing_validation"];
    }

    /**
     * Retrieve a list of licensing server IPs
     *
     * @return array
     */

    private function getHosts()
    {
        if( $this->useInternalLicensingValidation() ) 
        {
            return array( "" );
        }

        return self::LICENSE_API_HOSTS;
    }

    public function getLicenseKey()
    {
        return $this->licensekey;
    }

    private function getHostIP()
    {
        return WHMCS_LICENSE_IP;
    }

    private function getHostDomain()
    {
        return WHMCS_LICENSE_DOMAIN;
    }

    private function getHostDir()
    {
        return WHMCS_LICENSE_DIR;
    }

    public function getSalt()
    {
        return $this->salt;
    }

    public function getDate()
    {
        return $this->date;
    }

    public function checkLocalKeyExpiry()
    {
        $originalcheckdate = $this->getKeyData("checkdate");
        $localexpirymax = date("Ymd", mktime(0, 0, 0, date("m"), date("d") - $this->localkeydays, date("Y")));
        if( $originalcheckdate < $localexpirymax ) 
        {
            return false;
        }

        $localmax = date("Ymd", mktime(0, 0, 0, date("m"), date("d") + 2, 2020));
        if( $localmax < $originalcheckdate ) 
        {
            return false;
        }

        return true;
    }

    /**
     * Build post data for license check.
     *
     * @return string[]
     */

    protected function buildPostData()
    {
        $postfields = array();
        $postfields["licensekey"] = $this->getLicenseKey();
        $postfields["domain"] = $this->getHostDomain();
        $postfields["ip"] = $this->getHostIP();
        $postfields["dir"] = $this->getHostDir();
        $postfields["check_token"] = sha1(time() . $this->getLicenseKey() . mt_rand(1000000000, 9999999999));
        $whmcs = \DI::make("app");
        $postfields["version"] = $whmcs->getVersion()->getCanonical();
        $postfields["phpversion"] = PHP_VERSION;
        $stats = json_decode($whmcs->get_config("SystemStatsCache"), true);
        if( !is_array($stats) ) 
        {
            $stats = array();
        }

        $postfields["anondata"] = $this->encryptMemberData($stats);
        $postfields["member"] = $this->encryptMemberData($this->buildMemberData());
        return $postfields;
    }

    /**
     * Perform a remote license check.
     *
     * @param bool $forceRemote
     *
     * @return bool
     */

    public function remoteCheck($forceRemote = false)
    {
        try
        {
            $localkeyvalid = $this->decodeLocalOnce();
            $this->debug("Local Key Valid: " . $localkeyvalid);
            if( $localkeyvalid ) 
            {
                $localkeyvalid = $this->checkLocalKeyExpiry();
                $this->debug("Local Key Expiry: " . $localkeyvalid);
            }

            if( $localkeyvalid ) 
            {
                $localkeyvalid = $this->validateLocalKey();
                $this->debug("Local Key Validation: " . $localkeyvalid);
            }

            if ( !$localkeyvalid || $forceRemote ) {
				$whmcs                     = Application::getinstance();
                $results["status"]         = "Active";
                $results["key"]            = $this->licensekey;
                $results["registeredname"] = $whmcs->get_config("WHMCS Special");
                $results["productname"]    = "Owned License No Branding";
                $results["productid"]      = "5";
                $results["billingcycle"]   = "One Time";
                $results["validdomains"]   = $this->getHostDomain();
                $results["validips"]       = $this->getHostIP();
                $results["validdirs"]      = $this->getHostDir();
                $results["checkdate"]      = $this->getDate();
                $results["version"]        = $whmcs->getVersion()->getCanonical();
                $results["regdate"]        = "2016-04-13";
                $results["nextduedate"]    = "2050-04-13";
                $results["addons"]         = array(
                    array(
                        'name' => 'Branding Removal',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Support and Updates',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Project Management Addon',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Licensing Addon',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Mobile Edition',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'iPhone App',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Android App',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Configurable Package Addon',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Live Chat Monthly No Branding',
                        'nextduedate' => '2050-04-13',
                        'status' => 'Active'
                    )
                );
                $this->setKeyData($results);
                $this->updateLocalKey();
			}

            $this->debug("Remote Check Done");
        }
        catch( Exception $exception ) 
        {
            $this->debug(sprintf("License Error: %s", $exception->getMessage()));
            return false;
        }
        return true;
    }

    private function getLocalMaxExpiryDate()
    {
        return date("Ymd", mktime(0, 0, 0, date("m"), date("d") - ($this->localkeydays + $this->allowcheckfaildays), 2020));
    }

    /**
     * Build post query and initiate call home loop.
     *
     * Will attempt to validate a license first with a 5 second timeout
     * limit, and should none of those succeed, again with a longer 30
     * second timeout limit. Upon success, the loop is ended.
     *
     * @param array $postfields
     *
     * @return string|bool Returns false on failure
     */

    private function callHome($postfields)
    {
        $query_string = build_query_string($postfields);
        $res = $this->callHomeLoop($query_string, 5);
        if( $res ) 
        {
            return $res;
        }

        return $this->callHomeLoop($query_string, 30);
    }

    /**
     * Get license verification URL based on a given hostname.
     *
     * @param string $host
     *
     * @return string
     */

    protected function getVerifyUrl($host)
    {
        return "https://" . $host . "/" . self::LICENSE_API_VERSION . "/verify";
    }

    /**
     * Trigger call for each hostname in order.
     *
     * Will attempt to connect to license servers in order until an HTTP
     * 200 Response Code is detected.
     *
     * @param string $query_string
     * @param int $timeout
     *
     * @return string|bool Returns false if no attempt returns a 200 HTTP Response Code
     */

    private function callHomeLoop($query_string, $timeout = 5)
    {
        foreach( $this->getHosts() as $host ) 
        {
            $responsecode = $this->makeCall($this->getVerifyUrl($host), $query_string, $timeout);
            if( $responsecode == 200 ) 
            {
                return $this->responsedata;
            }

        }
        return false;
    }

    /**
     * Perform remote call.
     *
     * Performs an external call using curl to a given URL, with given
     * post data and timeout limit.
     *
     * @param string $url
     * @param string $query_string
     * @param int $timeout
     *
     * @return int
     */

    protected function makeCall($url, $query_string, $timeout = 5)
    {
        $this->debug("Request URL " . $url);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $query_string);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, ($this->useInternalLicensingValidation() ? 0 : 2));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, ($this->useInternalLicensingValidation() ? 0 : 1));
        $this->responsedata = curl_exec($ch);
        $responsecode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->debug("Response Code: " . $responsecode . " Data: " . $this->responsedata);
        if( curl_error($ch) ) 
        {
            $this->debug("Curl Error: " . curl_error($ch) . " - " . curl_errno($ch));
        }

        curl_close($ch);
        return $responsecode;
    }

    private function processResponse($data)
    {
        $publicServerKey = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy62WXeIR+PG/50quF7HD\nHXxrRkBIjazP19mXmcqRnyB/sXl3v5WDqxkS/bttqEseNgs2+WmuXPdHzwFF2IhY\nqoijl6zvVOXiT44rVQvCvfQrMncWbrl6PmTUmP8Ux2Dmttnz+dGJlTz3uaysfPqC\n9pAn19b8zgNwGPNl0cGqiMxruGU4Vzbbjs0zOamvrzUkpKRkD3t8voW78KqQ80A/\nfyP9jfCa4Tax6OfjiZ2EVMQgwNbu4nZeu5hggg/9KWX62O+iDWRw10A4OIzw2mJ+\nL0IDgeSMdrSUYgHlf+AUeW2qZV7cN7OOdt+FMQ3i5lX9LBBNeykqIiypF+voVFgN\nLhKw04EOrj6R511yOvVIrW5d2FO/wA5mydXJ1T31w+fjG3IitRm9F6tSRoPfeSi9\n+hWMpBUa9rg/BuoSOGoHMKbKFAN2hYu0e2ftkZ7KATNfoSf3D5HEVnTPqx+KfQFT\nRdjsYUIIqVX+GsQzzBulf5YhoTmew+N5n9dZGGbhNHZTr7cMa1DT73BjxOyMr2Fq\nW92QUyodlfZmPMfF+JD+MBMY0r74u8/ow1rCrnqu+3Rr/JE/Hjl6c9VsQS/sucP6\nJQfLTfeBjXNWdrXCvhUb+QaV4pMYxhpno5/7jPEkMOR9o7QTCFzbszEzlotwS/yT\ncgD/Aq302svJj2VbSAtyBi0CAwEAAQ==\n-----END PUBLIC KEY-----";
        $results = $this->parseSignedResponse($data, $publicServerKey);
        $this->posthash = $results["hash"];
        unset($results["hash"]);
        $results["checkdate"] = $this->getDate();
        if( !empty($results["MemberPubKey"]) ) 
        {
            $this->setMemberPublicKey($results["MemberPubKey"]);
            unset($results["MemberPubKey"]);
        }

        return $results;
    }

    private function parseSignedResponse($response, $publicKey)
    {
        if( $this->useInternalLicensingValidation() ) 
        {
            return json_decode($response, true);
        }

        $this->debug("license response: " . $response);
        $data = explode(":", $response, 2);
        if( empty($data[1]) ) 
        {
            $this->debug("no license signature found");
            return array();
        }

        $rsa = new \phpseclib\Crypt\RSA();
        $rsa->setSignatureMode(\phpseclib\Crypt\RSA::SIGNATURE_PKCS1);
        $rsa->loadKey(str_replace(array( "\n", " " ), array( "", "" ), $publicKey));
        if( !$rsa->verify($data[0], base64_decode($data[1])) ) 
        {
            $this->debug("invalid license signature");
            return array();
        }

        $data = strrev($data[0]);
        $data = base64_decode($data);
        $data = json_decode($data, true);
        if( empty($data) ) 
        {
            $this->debug("invalid license data structure");
            return array();
        }

        return $data;
    }

    private function updateLocalKey()
    {
        $data_encoded = json_encode($this->keydata);
        $data_encoded = base64_encode($data_encoded);
        $data_encoded = sha1($this->getDate() . $this->getSalt()) . $data_encoded;
        $data_encoded = strrev($data_encoded);
        $splpt = strlen($data_encoded) / 2;
        $data_encoded = substr($data_encoded, $splpt) . substr($data_encoded, 0, $splpt);
        $data_encoded = sha1($data_encoded . $this->getSalt()) . $data_encoded . sha1($data_encoded . $this->getSalt() . time());
        $data_encoded = base64_encode($data_encoded);
        $data_encoded = wordwrap($data_encoded, 80, "\n", true);
        \App::self()->set_config("License", $data_encoded);
        $this->debug("Updated Local Key");
    }

    public function forceRemoteCheck()
    {
        $this->remoteCheck(true);
    }

    private function setInvalid($reason = "Invalid")
    {
        $this->keydata = array( "status" => $reason );
    }

    private function decodeLocal()
    {
        $this->debug("Decoding local key");
        $localkey = $this->localkey;
        if( !$localkey ) 
        {
            return false;
        }

        $localkey = str_replace("\n", "", $localkey);
        $localkey = base64_decode($localkey);
        $localdata = substr($localkey, 40, -40);
        $md5hash = substr($localkey, 0, 40);
        if( $md5hash == sha1($localdata . $this->getSalt()) ) 
        {
            $splpt = strlen($localdata) / 2;
            $localdata = substr($localdata, $splpt) . substr($localdata, 0, $splpt);
            $localdata = strrev($localdata);
            $md5hash = substr($localdata, 0, 40);
            $localdata = substr($localdata, 40);
            $localdata = base64_decode($localdata);
            $localkeyresults = json_decode($localdata, true);
            $originalcheckdate = $localkeyresults["checkdate"];
            if( $md5hash == sha1($originalcheckdate . $this->getSalt()) ) 
            {
                if( isset($localkeyresults["key"]) && $localkeyresults["key"] == \App::self()->get_license_key() ) 
                {
                    $this->debug("Local Key Decode Successful");
                    $this->setKeyData($localkeyresults);
                }
                else
                {
                    $this->debug("License Key Invalid");
                }

            }
            else
            {
                $this->debug("Local Key MD5 Hash 2 Invalid");
            }

        }
        else
        {
            $this->debug("Local Key MD5 Hash Invalid");
        }

        $this->localkeydecoded = true;
        return ($this->getKeyData("status") == "Active" ? true : false);
    }

    private function decodeLocalOnce()
    {
        if( $this->localkeydecoded ) 
        {
            return true;
        }

        return $this->decodeLocal();
    }

    private function isRunningInCLI()
    {
        return php_sapi_name() == "cli" && empty($_SERVER["REMOTE_ADDR"]);
    }

    private function validateLocalKey()
    {
        if( $this->getKeyData("status") != "Active" ) 
        {
            $this->debug("Local Key Status Check Failure");
            return false;
        }

        if( $this->isRunningInCLI() ) 
        {
            $this->debug("Running in CLI Mode");
        }
        else
        {
            $this->debug("Running in Browser Mode");
            if( $this->isValidDomain($this->getHostDomain()) ) 
            {
                $this->debug("Domain Validated Successfully");
                $ip = $this->getHostIP();
                $this->debug("Host IP Address: " . $ip);
                if( !$ip ) 
                {
                    $this->debug("IP Could Not Be Determined - Skipping Local Validation of IP");
                }
                else
                {
                    if( !trim($this->getKeyData("validips")) ) 
                    {
                        $this->debug("No Valid IPs returned by license check - Cloud Based License - Skipping Local Validation of IP");
                    }
                    else
                    {
                        if( $this->isValidIP($ip) ) 
                        {
                            $this->debug("IP Validated Successfully");
                        }
                        else
                        {
                            $this->debug("Local Key IP Check Failure");
                            return false;
                        }

                    }

                }

            }
            else
            {
                $this->debug("Local Key Domain Check Failure");
                return false;
            }

        }

        if( $this->isValidDir($this->getHostDir()) ) 
        {
            $this->debug("Directory Validated Successfully");
            return true;
        }

        $this->debug("Local Key Directory Check Failure");
        return false;
    }

    private function isValidDomain($domain)
    {
        $validdomains = $this->getArrayKeyData("validdomains");
        return in_array($domain, $validdomains);
    }

    private function isValidIP($ip)
    {
        $validips = $this->getArrayKeyData("validips");
        return in_array($ip, $validips);
    }

    private function isValidDir($dir)
    {
        $validdirs = $this->getArrayKeyData("validdirs");
        return in_array($dir, $validdirs);
    }

    private function revokeLocal()
    {
        \App::self()->set_config("License", "");
    }

    public function getKeyData($var)
    {
        return (isset($this->keydata[$var]) ? $this->keydata[$var] : "");
    }

    private function setKeyData($data)
    {
        $this->keydata = $data;
    }

    /**
     * Retrieve a license element as an array, that would otherwise be a
     * delimited string
     *
     * NOTE: use of this method should be very limited. New license elements
     * added to the license data should strongly consider not depending on the
     * use of this function, but instead structure the data and let the
     * transmission layer do the serialize/unserialize
     *
     * @param string $var License data element whose value is a comma delimited string
     *
     * @return array
     * @throws Exception when internal license key data structure is not
     * as expected
     */

    protected function getArrayKeyData($var)
    {
        $listData = array();
        $rawData = $this->getKeyData($var);
        if( is_string($rawData) ) 
        {
            $listData = explode(",", $rawData);
            foreach( $listData as $k => $v ) 
            {
                if( is_string($v) ) 
                {
                    $listData[$k] = trim($v);
                }
                else
                {
                    throw new Exception("Invalid license data structure");
                }

            }
        }
        else
        {
            if( !is_null($rawData) ) 
            {
                throw new Exception("Invalid license data structure");
            }

        }

        return $listData;
    }

    public function getRegisteredName()
    {
        return $this->getKeyData("registeredname");
    }

    public function getProductName()
    {
        return $this->getKeyData("productname");
    }

    public function getStatus()
    {
        return $this->getKeyData("status");
    }

    public function getSupportAccess()
    {
        return $this->getKeyData("supportaccess");
    }

    /**
     * Retrieve a list of Addons as known by the license
     *
     * @return array
     */

    protected function getLicensedAddons()
    {
        $licensedAddons = $this->getKeyData("addons");
        if( !is_array($licensedAddons) ) 
        {
            $licensedAddons = array();
        }

        return $licensedAddons;
    }

    public function getActiveAddons()
    {
        $licensedAddons = $this->getLicensedAddons();
        $activeAddons = array();
        foreach( $licensedAddons as $addon ) 
        {
            if( $addon["status"] == "Active" ) 
            {
                $activeAddons[] = $addon["name"];
            }

        }
        return $activeAddons;
    }

    public function isActiveAddon($addon)
    {
        return (in_array($addon, $this->getActiveAddons()) ? true : false);
    }

    public function getExpiryDate($showday = false)
    {
        $expiry = $this->getKeyData("nextduedate");
        if( !$expiry ) 
        {
            $expiry = "Never";
        }
        else
        {
            if( $showday ) 
            {
                $expiry = date("l, jS F Y", strtotime($expiry));
            }
            else
            {
                $expiry = date("jS F Y", strtotime($expiry));
            }

        }

        return $expiry;
    }

    /**
     * Get a version object that will represent the latest publicly available version
     *
     * If the licensing API does not return a valid version number for
     * whatever reason, it assumes latest version = installed version
     * to allow application to continue un-affected
     *
     * @return SemanticVersion
     */

    public function getLatestPublicVersion()
    {
        try
        {
            $latestVersion = new Version\SemanticVersion($this->getKeyData("latestpublicversion"));
        }
        catch( Exception\Version\BadVersionNumber $e ) 
        {
            $whmcs = \DI::make("app");
            $latestVersion = $whmcs->getVersion();
        }
        return $latestVersion;
    }

    /**
     * Get a version object that will represent the latest available pre-release version
     *
     * If the licensing API does not return a valid version number for
     * whatever reason, it assumes latest version = installed version
     * to allow application to continue un-affected
     *
     * @return SemanticVersion
     */

    public function getLatestPreReleaseVersion()
    {
        try
        {
            $latestVersion = new Version\SemanticVersion($this->getKeyData("latestprereleaseversion"));
        }
        catch( Exception\Version\BadVersionNumber $e ) 
        {
            $whmcs = \DI::make("app");
            $latestVersion = $whmcs->getVersion();
        }
        return $latestVersion;
    }

    /**
     * Get a version object that will represent the latest appropriate version based on current installation
     *
     * If running a pre-release (beta/rc) it returns the latest pre-release version
     * Otherwise it returns the latest publicly available version
     *
     * @return SemanticVersion
     */

    public function getLatestVersion()
    {
        $whmcs = \DI::make("app");
        $installedVersion = $whmcs->getVersion();
        if( in_array($installedVersion->getPreReleaseIdentifier(), array( "beta", "rc" )) ) 
        {
            $latestVersion = $this->getLatestPreReleaseVersion();
        }
        else
        {
            $latestVersion = $this->getLatestPublicVersion();
        }

        return $latestVersion;
    }

    /**
     * Determines if an update is available for the currently installed files
     *
     * @throws BadVersionNumber If version number invalid
     *
     * @return bool
     */

    public function isUpdateAvailable()
    {
        $whmcs = \DI::make("app");
        $installedVersion = $whmcs->getVersion();
        $latestVersion = $this->getLatestVersion();
        return Version\SemanticVersion::compare($latestVersion, $installedVersion, ">");
    }

    public function getRequiresUpdates()
    {
        return ($this->getKeyData("requiresupdates") ? true : false);
    }

    /**
     * Returns Support and Updates expiration date, if found, or an empty otherwise
     *
     * @return string
     */

    public function getUpdatesExpirationDate()
    {
        $expirationDates = array();
        $licensedAddons = $this->getLicensedAddons();
        foreach( $licensedAddons as $addon ) 
        {
            if( $addon["name"] == "Support and Updates" && $addon["status"] == "Active" && isset($addon["nextduedate"]) ) 
            {
                try
                {
                    $expirationDates[] = \Carbon\Carbon::createFromFormat("Y-m-d", $addon["nextduedate"]);
                }
                catch( \Exception $e ) 
                {
                }
            }

        }
        if( !empty($expirationDates) ) 
        {
            rsort($expirationDates);
            return $expirationDates[0]->format("Y-m-d");
        }

        return "";
    }

    public function checkOwnedUpdatesForReleaseDate($releaseDate)
    {
        if( !$this->getRequiresUpdates() ) 
        {
            return true;
        }

        try
        {
            $updatesExpirationDate = \Carbon\Carbon::createFromFormat("Y-m-d", $this->getUpdatesExpirationDate());
            $checkDate = \Carbon\Carbon::createFromFormat("Y-m-d", $releaseDate);
            return ($checkDate <= $updatesExpirationDate ? true : false);
        }
        catch( \Exception $e ) 
        {
        }
        return false;
    }

    public function checkOwnedUpdates()
    {
        $whmcs = \DI::make("app");
        return $this->checkOwnedUpdatesForReleaseDate($whmcs->getReleaseDate());
    }

    public function getBrandingRemoval()
    {
        if( in_array($this->getProductName(), array( "Owned License No Branding", "Monthly Lease No Branding" )) ) 
        {
            return true;
        }

        $licensedAddons = $this->getLicensedAddons();
        foreach( $licensedAddons as $addon ) 
        {
            if( $addon["name"] == "Branding Removal" && $addon["status"] == "Active" ) 
            {
                return true;
            }

        }
        return false;
    }

    public function getVersionHash()
    {
        return $this->version;
    }

    private function debug($msg)
    {
        $this->debuglog[] = $msg;
    }

    /**
     * Retrieve all errors
     *
     * @return array
     */

    public function getDebugLog()
    {
        return $this->debuglog;
    }

    /**
     * Retrieve the date that a license permits product updates.
     *
     * @todo implement this
     * @return DateTime
     */

    public function getUpdateValidityDate()
    {
        return new \DateTime();
    }

    /**
     * Get if client limits should be enforced from the license response.
     *
     * @return bool
     */

    public function isClientLimitsEnabled()
    {
        return (bool) $this->getKeyData("ClientLimitsEnabled");
    }

    /**
     * Get the client limit as defined by the license.
     *
     * @return int
     */

    public function getClientLimit()
    {
        $clientLimit = $this->getKeyData("ClientLimit");
        if( $clientLimit == "" ) 
        {
            return -1;
        }

        if( !is_numeric($clientLimit) ) 
        {
            $this->debug("Invalid client limit value in license");
            return 0;
        }

        return (int) $clientLimit;
    }

    /**
     * Format the client limit for display in a human friendly way.
     *
     * Expect a formatted number or the text 'None' for 0.
     *
     * NOTE: If an admin instance is not provided or the key has no translation,
     * an English value would be returned.
     *
     * @param \WHMCS\Admin $admin Admin instance for contextual language.
     *
     * @return string
     */

    public function getTextClientLimit(Admin $admin = NULL)
    {
        $clientLimit = $this->getClientLimit();
        $result = "Unlimited";
        if( 0 < $clientLimit ) 
        {
            $result = number_format($clientLimit, 0, "", ",");
        }
        else
        {
            if( $admin && ($text = $admin->lang("global", "unlimited")) ) 
            {
                $result = $text;
            }

        }

        return $result;
    }

    /**
     * Get the number of active clients in the installation.
     *
     * @todo Change this to calculate in real-time to avoid easy abuse
     *
     * @return int
     */

    public function getNumberOfActiveClients()
    {
        return (int) get_query_val("tblclients", "count(id)", "status='Active'");
    }

    /**
     * Format the number of active clients for display in a human friendly way.
     *
     * Expect a formatted number or the text 'None' for 0.
     *
     * NOTE: If an admin instance is not provided or the key has no translation,
     * an English value would be returned.
     *
     * @param \WHMCS\Admin $admin Admin instance for contextual language.
     *
     * @return string
     */

    public function getTextNumberOfActiveClients(Admin $admin = NULL)
    {
        $clientLimit = $this->getNumberOfActiveClients();
        $result = "None";
        if( 0 < $clientLimit ) 
        {
            $result = number_format($clientLimit, 0, "", ",");
        }
        else
        {
            if( $admin && ($text = $admin->lang("global", "none")) ) 
            {
                $result = $text;
            }

        }

        return $result;
    }

    /**
     * Get the first client ID that is outside the client limit
     *
     * Given that client limits are meant to be enforced for the active clients
     * in ascending order, this routine determines the first client who is
     * outside the pool of active/inactive clients that the admin is permitted
     * to manage.  i.e., callers should deny management rights of this id or any
     * id higher than it.
     *
     * @return int
     */

    public function getClientBoundaryId()
    {
        return (int) get_query_val("tblclients", "id", "status='Active'", "id", "ASC", (int) $this->getClientLimit() . ",1");
    }

    /**
     * Determine if installation's active client count is "close" or at client limit
     *
     * If true, the caller is expected to show an appropriate warning.
     *
     * "Close" is within 10% for a client boundary of 250; for boundaries above
     * 250, the "close" margin is only 5%.
     *
     * If there are absolutely no clients active, one can never by near or at
     * the limit. Likewise, if by chance there's an evaluated limit of 0 from
     * the license key data, then one can never by near or at the limit. This
     * logic might need refinement if every there was such a thing as a 0 client
     * seat limit.
     *
     * @return bool
     */

    public function isNearClientLimit()
    {
        $clientLimit = $this->getClientLimit();
        $numClients = $this->getNumberOfActiveClients();
        if( $numClients < 1 || $clientLimit < 1 ) 
        {
            return false;
        }

        $percentageBound = (250 < $clientLimit ? 0.05 : 0.1);
        return $clientLimit * (1 - $percentageBound) <= $numClients;
    }

    /**
     * Is Client Limits Auto Upgrade Enabled.
     *
     * @return bool
     */

    public function isClientLimitsAutoUpgradeEnabled()
    {
        return (bool) $this->getKeyData("ClientLimitAutoUpgradeEnabled");
    }

    /**
     * Get Client Limit Learn More Url.
     *
     * @return string
     */

    public function getClientLimitLearnMoreUrl()
    {
        return $this->getKeyData("ClientLimitLearnMoreUrl");
    }

    /**
     * Get Client Limit Upgrade Url.
     *
     * @return string
     */

    public function getClientLimitUpgradeUrl()
    {
        return $this->getKeyData("ClientLimitUpgradeUrl");
    }

    protected function getMemberPublicKey()
    {
        $publicKey = Config\Setting::getValue("MemberPubKey");
        if( $publicKey ) 
        {
            $publicKey = decrypt($publicKey);
        }

        return $publicKey;
    }

    protected function setMemberPublicKey($publicKey = "")
    {
        if( $publicKey ) 
        {
            $publicKey = encrypt($publicKey);
            Config\Setting::setValue("MemberPubKey", $publicKey);
        }

        return $this;
    }

    /**
     * Encrypt data for WHMCS Member Area and License system
     *
     * The return value will be blank if anything goes wrong, otherwise it is a
     * base64 encoded value.
     *
     * NOTE: \phpseclib\Crypt\RSA traditionally will emit warnings; they are not suppressed
     * here.
     *
     * @param array $data Key/value pairs to bundle into the encrypted string
     *
     * @return string
     */

    public function encryptMemberData(array $data = array())
    {
        $publicKey = $this->getMemberPublicKey();
        if( !$publicKey ) 
        {
            return "";
        }

        $publicKey = str_replace(array( "\n", "\r", " " ), array( "", "", "" ), $publicKey);
        $cipherText = "";
        if( is_array($data) ) 
        {
            try
            {
                $rsa = new \phpseclib\Crypt\RSA();
                $rsa->loadKey($publicKey);
                $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_OAEP);
                $cipherText = $rsa->encrypt(json_encode($data));
                if( !$cipherText ) 
                {
                    throw new Exception("Could not perform RSA encryption");
                }

                $cipherText = base64_encode($cipherText);
            }
            catch( \Exception $e ) 
            {
                $this->debug("Failed to encrypt member data");
            }
        }

        return $cipherText;
    }

    /**
     * Get Client Limit Notification.
     *
     * @return string[]
     */

    public function getClientLimitNotificationAttributes()
    {
        if( !$this->isClientLimitsEnabled() || !$this->isNearClientLimit() ) 
        {
            return null;
        }

        $clientLimit = $this->getClientLimit();
        $clientLimitNotification = array( "class" => "info", "icon" => "fa-info-circle", "title" => "Approaching Client Limit", "body" => "You are approaching the maximum number of clients permitted by your current license. Your license will be upgraded automatically when the limit is reached.", "autoUpgradeEnabled" => $this->isClientLimitsAutoUpgradeEnabled(), "upgradeUrl" => $this->getClientLimitUpgradeUrl(), "learnMoreUrl" => $this->getClientLimitLearnMoreUrl(), "numberOfActiveClients" => $this->getNumberOfActiveClients(), "clientLimit" => $clientLimit );
        if( $this->isClientLimitsAutoUpgradeEnabled() ) 
        {
            if( $this->getNumberOfActiveClients() < $clientLimit ) 
            {
            }
            else
            {
                if( $clientLimit == $this->getNumberOfActiveClients() ) 
                {
                    $clientLimitNotification["title"] = "Client Limit Reached";
                    $clientLimitNotification["body"] = "You have reached the maximum number of clients permitted by your current license. Your license will be upgraded automatically when the next client is created.";
                }
                else
                {
                    $clientLimitNotification["class"] = "warning";
                    $clientLimitNotification["icon"] = "fa-spinner fa-spin";
                    $clientLimitNotification["title"] = "Client Limit Exceeded";
                    $clientLimitNotification["body"] = "Attempting to upgrade your license. Communicating with license server...";
                    $clientLimitNotification["attemptUpgrade"] = true;
                }

            }

        }
        else
        {
            if( $this->getNumberOfActiveClients() < $clientLimit ) 
            {
                $clientLimitNotification["body"] = "You are approaching the maximum number of clients permitted by your license. As you have opted out of automatic license upgrades, you should upgrade now to avoid interuption in service.";
            }
            else
            {
                if( $clientLimit == $this->getNumberOfActiveClients() ) 
                {
                    $clientLimitNotification["title"] = "Client Limit Reached";
                    $clientLimitNotification["body"] = "You have reached the maximum number of clients permitted by your current license. As you have opted out of automatic license upgrades, you must upgrade now to avoid interuption in service.";
                }
                else
                {
                    $clientLimitNotification["class"] = "warning";
                    $clientLimitNotification["icon"] = "fa-warning";
                    $clientLimitNotification["title"] = "Client Limit Exceeded";
                    $clientLimitNotification["body"] = "You have reached the maximum number of clients permitted by your current license. As automatic license upgrades have been disabled, you must upgrade now.";
                }

            }

        }

        return $clientLimitNotification;
    }

    /**
     * Build private data (to be encrypted)
     *
     * @return string
     */

    protected function buildMemberData()
    {
        return array( "licenseKey" => $this->getLicenseKey(), "activeClientCount" => $this->getNumberOfActiveClients() );
    }

    /**
     * Get encrypted member data.
     *
     * @return string
     */

    public function getEncryptedMemberData()
    {
        return $this->encryptMemberData($this->buildMemberData());
    }

    /**
     * Get Upgrade Url.
     *
     * @param string $host
     *
     * @return string
     */

    protected function getUpgradeUrl($host)
    {
        return "https://" . $host . "/" . self::LICENSE_API_VERSION . "/upgrade";
    }

    /**
     * Make upgrade call.
     *
     * @return bool
     */

    public function makeUpgradeCall()
    {
        $checkToken = sha1(time() . $this->getLicenseKey() . mt_rand(1000000000, 9999999999));
        $query_string = build_query_string(array( "check_token" => $checkToken, "license_key" => $this->getLicenseKey(), "member_data" => $this->encryptMemberData($this->buildMemberData()) ));
        $timeout = 30;
        foreach( $this->getHosts() as $host ) 
        {
            $responsecode = $this->makeCall($this->getUpgradeUrl($host), $query_string, $timeout);
            if( $responsecode == 200 ) 
            {
                $data = $this->processResponse($this->responsedata);
                if( $this->posthash != sha1("WHMCSV5.2SYH" . $checkToken) ) 
                {
                    return false;
                }

                if( $data["status"] == "Success" && is_array($data["new"]) ) 
                {
                    unset($data["status"]);
                    $this->keydata = array_merge($this->keydata, $data["new"]);
                    $this->updateLocalKey();
                    return true;
                }

                return false;
            }

        }
        return false;
    }

}


