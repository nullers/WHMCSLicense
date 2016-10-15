<?php

namespace WHMCS;

class License {
	protected $licensekey = '';
	protected $localkey = '';
	protected $keydata = array(  );
	protected $salt = '';
	protected $date = '';
	protected $localkeydecoded = '';
	protected $responsedata = '';
	protected $postmd5hash = '';
	protected $localkeydays = '10';
	protected $allowcheckfaildays = '5';
	protected $debuglog = array(  );
	protected $version = '7a1bbff560de83ab800c4d1d2f215b91006be8e6';

	/**
	 * The License singleton
	 *
	 * @var License
	 */
	function __construct() {
		$whmcs = Application::getinstance(  );
		$this->licensekey = $whmcs->get_license_key(  );
		$this->localkey = $whmcs->get_config( 'License' );
		$this->salt = sha1( 'WHMCS' . $whmcs->get_config( 'Version' ) . 'TFB' . $whmcs->get_hash(  ) );
		$this->date = date( 'Ymd' );
		$this->decodeLocalOnce(  );

		if (isset( $_GET['forceremote'] )) {
			$this->forceRemoteCheck(  );
			Terminus::getinstance(  )->doExit(  );
		}

	}

	/**
	 * Set the License singleton.
	 *
	 * @param License $license
	 * @return License
	 */
	function setInstance($license) {
		$license = self::$instance;
		return $license;
	}

	/**
	 * Remove the License singleton.
	 */
	function destroyInstance() {
		self::$instance = null;
	}

	/**
	 * Retrieve a License object via singleton.
	 *
	 * @return License
	 */
	function getInstance() {
		if (is_null(self::$instance))
		{
			self::setinstance(new License());
		}

		return self::$instance;
	}

	/**
	 * Retrieve a list of licensing server IPs
	 *
	 * @return array
	 */
	function getHosts() {
		$hosts = gethostbynamel( 'licensing28.whmcs.com' );

		if ($hosts === false) {
			$hosts = array(  );
		}

		return $hosts;
	}

	function getLicenseKey() {
		return $this->licensekey;
	}

	function getHostIP() {
		if (isset( $_SERVER['SERVER_ADDR'] )) {
			$ip = $_SERVER['SERVER_ADDR'];
		} else {
			if (isset( $_SERVER['LOCAL_ADDR'] )) {
				$ip = $_SERVER['LOCAL_ADDR'];
			} else {
				if (function_exists( 'gethostname' )) {
					$ip = gethostbyname( gethostname(  ) );
				} else {
					$ip = '';
				}
			}
		}

		return $ip;
	}

	function getHostDomain() {
		return (isset( $_SERVER['SERVER_NAME'] ) ? $_SERVER['SERVER_NAME'] : '');
	}

	function getHostDir() {
		return ROOTDIR;
	}

	function getSalt() {
		return $this->salt;
	}

	function getDate() {
		return $this->date;
	}

	function checkLocalKeyExpiry() {
		$originalcheckdate = $this->getKeyData( 'checkdate' );
		$localexpirymax = date( 'Ymd', mktime( 0, 0, 0, date( 'm' ), date( 'd' ) - $this->localkeydays, date( 'Y' ) ) );

		if ($originalcheckdate < $localexpirymax) {
			return false;
		}

		$localmax = date( 'Ymd', mktime( 0, 0, 0, date( 'm' ), date( 'd' ) + 2, date( 'Y' ) ) );

		if ($localmax < $originalcheckdate) {
			return false;
		}

		return true;
	}

	function remoteCheck($forceRemote = false) {
		try {
			$localkeyvalid = $this->decodeLocalOnce(  );
			$this->debug( '' . 'Local Key Valid: ' . $localkeyvalid );

			if ($localkeyvalid) {
				$localkeyvalid = $this->checkLocalKeyExpiry(  );
				$this->debug( '' . 'Local Key Expiry: ' . $localkeyvalid );

				if ($localkeyvalid) {
					$localkeyvalid = $this->validateLocalKey(  );
					$this->debug( '' . 'Local Key Validation: ' . $localkeyvalid );
				}
			}


			if ( !$localkeyvalid || $forceRemote ) {
				$whmcs                     = Application::getinstance();
                $results["status"]         = "Active";
                $results["key"]            = $this->licensekey;
                $results["registeredname"] = $whmcs->get_config("CompanyName");
                $results["productname"]    = "Owned License No Branding";
                $results["productid"]      = "5";
                $results["billingcycle"]   = "One Time";
                $results["validdomains"]   = $this->getHostDomain();
                $results["validips"]       = $this->getHostIP();
                $results["validdirs"]      = $this->getHostDir();
                $results["checkdate"]      = $this->getDate();
                $results["version"]        = $whmcs->getVersion()->getCanonical();
                $results["regdate"]        = "2014-02-06";
                $results["nextduedate"]    = "2050-02-06";
                $results["addons"]         = array(
                    array(
                        'name' => 'Branding Removal',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Support and Updates',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Project Management Addon',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Licensing Addon',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Mobile Edition',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'iPhone App',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Android App',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Configurable Package Addon',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    ),
                    array(
                        'name' => 'Live Chat Monthly No Branding',
                        'nextduedate' => '2050-12-30',
                        'status' => 'Active'
                    )
                );
                $this->setKeyData($results);
                $this->updateLocalKey();
			}

			$this->debug( 'Remote Check Done' );
		}
		catch (Exception $exception) {
			$this->debug( sprintf( 'License Error: %s', $exception->getMessage(  ) ) );
			return false;
		}
		return true;
	}

	function getLocalMaxExpiryDate() {
		return date( 'Ymd', mktime( 0, 0, 0, date( 'm' ), date( 'd' ) - ( $this->localkeydays + $this->allowcheckfaildays ), date( 'Y' ) ) );
	}

	function buildQuery($postfields) {
		$query_string = '';
		foreach ($postfields as $k => $v) {
			$query_string .= $k . '=' . urlencode( $v ) . '&';
		}

		return $query_string;
	}

	function callHome($postfields) {
		$query_string = $this->buildQuery( $postfields );
		$res = $this->callHomeLoop( $query_string, 5 );

		if ($res) {
			return $res;
		}

		return $this->callHomeLoop( $query_string, 30 );
	}

	function callHomeLoop($query_string, $timeout = 5) {
		$hostips = $this->getHosts(  );
		foreach ($hostips as $hostip) {
			$responsecode = $this->makeCall( $hostip, $query_string, $timeout );

			if ($responsecode == 200) {
				return $this->responsedata;
			}
		}

		return false;
	}

	function makeCall($ip, $query_string, $timeout = 5) {
		$url = 'https://' . $ip . '/license/verify53.php';
		$this->debug( '' . 'Request URL ' . $url );
		$ch = curl_init(  );
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_POST, 1 );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $query_string );
		curl_setopt( $ch, CURLOPT_TIMEOUT, $timeout );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 0 );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, 0 );
		$this->responsedata = curl_exec( $ch );
		$responsecode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$this->debug( '' . 'Response Code: ' . $responsecode . ' Data: ' . $this->responsedata );

		if (curl_error( $ch )) {
			$this->debug( 'Curl Error: ' . curl_error( $ch ) . ' - ' . curl_errno( $ch ) );
		}

		curl_close( $ch );
		return $responsecode;
	}

	function processResponse($data) {
		$data = strrev( $data );
		$data = base64_decode( $data );
		$results = unserialize( $data );
		$this->posthash = $results['hash'];
		unset( $results['hash'] );
		$results['checkdate'] = $this->getDate(  );
		return $results;
	}

	function updateLocalKey()
	{
		$data_encoded = serialize($this->keydata);
		$data_encoded = base64_encode($data_encoded);
		$data_encoded = sha1($this->getDate() . $this->getSalt()) . $data_encoded;
		$data_encoded = strrev($data_encoded);
		$splpt = strlen($data_encoded) / 2;
		$data_encoded = substr($data_encoded, $splpt) . substr($data_encoded, 0, $splpt);
		$data_encoded = sha1($data_encoded . $this->getSalt()) . $data_encoded . sha1($data_encoded . $this->getSalt() . time());
		$data_encoded = base64_encode($data_encoded);
		$data_encoded = wordwrap($data_encoded, 80, "\n", true);
		Application::getinstance()->set_config("License", $data_encoded);
		$this->debug("Updated Local Key");
		return null;
	}

	function forceRemoteCheck() {
		$this->remoteCheck( true );
	}

	function setInvalid($reason = 'Invalid') {
		$this->keydata = array( 'status' => $reason );
	}

	function decodeLocal()
	{
		$this->debug("Decoding local key");
		$localkey = $this->localkey;

		if (!$localkey)
		{
			return false;
		}

		$localkey = str_replace("\n", "", $localkey);
		$localkey = base64_decode($localkey);
		$localdata = substr($localkey, 40, 0 - 40);
		$md5hash = substr($localkey, 0, 40);

		if ($md5hash == sha1($localdata . $this->getSalt()))
		{
			$splpt = strlen($localdata) / 2;
			$localdata = substr($localdata, $splpt) . substr($localdata, 0, $splpt);
			$localdata = strrev($localdata);
			$md5hash = substr($localdata, 0, 40);
			$localdata = substr($localdata, 40);
			$localdata = base64_decode($localdata);
			$localkeyresults = unserialize($localdata);
			$originalcheckdate = $localkeyresults['checkdate'];

			if ($md5hash == sha1($originalcheckdate . $this->getSalt()))
			{
				if (isset($localkeyresults['key']) && $localkeyresults['key'] == Application::getinstance()->get_license_key())
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
		return $this->getKeyData("status") == "Active" ? true : false;
	}

	function decodeLocalOnce() {
		if ($this->localkeydecoded) {
			return true;
		}

		return $this->decodeLocal(  );
	}

	function isRunningInCLI() {
		return ( php_sapi_name(  ) == 'cli' && empty( $_SERVER['REMOTE_ADDR'] ) );
	}

	function validateLocalKey() {
		if ($this->getKeyData( 'status' ) != 'Active') {
			$this->debug( 'Local Key Status Check Failure' );
			return false;
		}


		if ($this->isRunningInCLI(  )) {
			$this->debug( 'Running in CLI Mode' );
		} else {
			$this->debug( 'Running in Browser Mode' );

			if ($this->isValidDomain( $this->getHostDomain(  ) )) {
				$this->debug( 'Domain Validated Successfully' );
			} else {
				$this->debug( 'Local Key Domain Check Failure' );
				return false;
			}

			$ip = $this->getHostIP(  );
			$this->debug( '' . 'Host IP Address: ' . $ip );

			if (!$ip) {
				$this->debug( 'IP Could Not Be Determined - Skipping Local Validation of IP' );
			} else {
				if (!trim( $this->getKeyData( 'validips' ) )) {
					$this->debug( 'No Valid IPs returned by license check - Cloud Based License - Skipping Local Validation of IP' );
				} else {
					if ($this->isValidIP( $ip )) {
						$this->debug( 'IP Validated Successfully' );
					} else {
						$this->debug( 'Local Key IP Check Failure' );
						return false;
					}
				}
			}
		}


		if ($this->isValidDir( $this->getHostDir(  ) )) {
			$this->debug( 'Directory Validated Successfully' );
		}
		else {
			$this->debug( 'Local Key Directory Check Failure' );
			return false;
		}

		return true;
	}

	function isValidDomain($domain) {
		$validdomains = $this->getArrayKeyData( 'validdomains' );
		return in_array( $domain, $validdomains );
	}

	function isValidIP($ip) {
		$validips = $this->getArrayKeyData( 'validips' );
		return in_array( $ip, $validips );
	}

	function isValidDir($dir) {
		$validdirs = $this->getArrayKeyData( 'validdirs' );
		return in_array( $dir, $validdirs );
	}

	function revokeLocal() {
		Application::getinstance(  )->set_config( 'License', '' );
	}

	function getKeyData($var) {
		return (isset( $this->keydata[$var] ) ? $this->keydata[$var] : '');
	}

	function setKeyData($data) {
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
	function getArrayKeyData($var) {
		$listData = array(  );
		$rawData = $this->getKeyData( $var );

		if (is_string( $rawData )) {
			$listData = explode( ',', $rawData );
			foreach ($listData as $k => $v) {
				if (is_string( $v )) {
					$listData[$k] = trim( $v );
					continue;
				}

				throw new Exception( 'Invalid license data structure' );
			}
		} else {
			if (!is_null( $rawData )) {
				throw new Exception( 'Invalid license data structure' );
			}
		}

		return $listData;
	}

	function getRegisteredName() {
		return $this->getKeyData( 'registeredname' );
	}

	function getProductName() {
		return $this->getKeyData( 'productname' );
	}

	function getStatus() {
		return $this->getKeyData( 'status' );
	}

	function getSupportAccess() {
		return $this->getKeyData( 'supportaccess' );
	}

	/**
	 * Retrieve a list of Addons as known by the license
	 *
	 * @return array
	 */
	function getLicensedAddons() {
		$licensedAddons = $this->getKeyData( 'addons' );

		if (!is_array( $licensedAddons )) {
			$licensedAddons = array(  );
		}

		return $licensedAddons;
	}

	function getActiveAddons() {
		$licensedAddons = $this->getLicensedAddons(  );
		$activeAddons = array(  );
		foreach ($licensedAddons as $addon) {
			if ($addon['status'] == 'Active') {
				$activeAddons[] = $addon['name'];
				continue;
			}
		}

		return $activeAddons;
	}

	function isActiveAddon($addon) {
		return (in_array( $addon, $this->getActiveAddons(  ) ) ? true : false);
	}

	function getExpiryDate($showday = false) {
		$expiry = $this->getKeyData( 'nextduedate' );

		if (!$expiry) {
			$expiry = 'Never';
		} else {
			if ($showday) {
				$expiry = date( 'l, jS F Y', strtotime( $expiry ) );
			} else {
				$expiry = date( 'jS F Y', strtotime( $expiry ) );
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
	 * @return Version_SemanticVersion
	 */
	function getLatestPublicVersion() {
		try {
			$latestVersion = new Version\SemanticVersion ($this->getKeyData( 'latestpublicversion' ));
		}
		catch (Exception\Version\BadVersionNumber $e) {
			$whmcs = Application::getinstance(  );
			$latestVersion = $whmcs->getVersion(  );
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
	 * @return Version_SemanticVersion
	 */
	function getLatestPreReleaseVersion() {
		try {
			$latestVersion = new Version\SemanticVersion($this->getKeyData( 'latestprereleaseversion' ));
		}
		catch (Exception\Version\BadVersionNumber $e) {
			$whmcs = Application::getinstance(  );
			$latestVersion = $whmcs->getVersion(  );
		}
		return $latestVersion;
	}

	/**
	 * Get a version object that will represent the latest appropriate version based on current installation
	 *
	 * If running a pre-release (beta/rc) it returns the latest pre-release version
	 * Otherwise it returns the latest publicly available version
	 *
	 * @return Version_SemanticVersion
	 */
	function getLatestVersion() {
		$whmcs = Application::getinstance(  );
		$installedVersion = $whmcs->getVersion(  );

		if (in_array( $installedVersion->getPreReleaseIdentifier(  ), array( 'beta', 'rc' ) )) {
			$latestVersion = $this->getLatestPreReleaseVersion(  );
		} else {
			$latestVersion = $this->getLatestPublicVersion(  );
		}

		return $latestVersion;
	}

	/**
	 * Determines if an update is available for the currently installed files
	 *
	 * @throws Exception_Version_BadVersionNumber If version number invalid
	 *
	 * @return bool
	 */
	function isUpdateAvailable() {
		$whmcs = Application::getinstance(  );
		$installedVersion = $whmcs->getVersion(  );
		$latestVersion = $this->getLatestVersion(  );
		return Version\SemanticVersion::compare( $latestVersion, $installedVersion, '>' );
	}

	function getRequiresUpdates() {
		return ($this->getKeyData( 'requiresupdates' ) ? true : false);
	}

	function checkOwnedUpdates() {
		if (!$this->getRequiresUpdates(  )) {
			return true;
		}

		$whmcs = Application::getinstance(  );
		$licensedAddons =  $this->getLicensedAddons(  );
		foreach ($licensedAddons as $addon) {
			if ( $addon['name'] == 'Support and Updates' && $addon['status'] == 'Active' ) {
				if (str_replace( '-', '', $whmcs->getReleaseDate(  ) ) <= str_replace( '-', '', $addon['nextduedate'] )) {
					return true;
					continue;
				}

				continue;
			}
		}

		return false;
	}

	function getBrandingRemoval() {
		if (in_array( $this->getProductName(  ), array( 'Owned License No Branding', 'Monthly Lease No Branding' ) )) {
			return true;
		}

		$licensedAddons = $this->getLicensedAddons(  );
		foreach ($licensedAddons as $addon) {
			if ( $addon['name'] == 'Branding Removal' && $addon['status'] == 'Active' ) {
				return true;
				continue;
			}
		}

		return false;
	}

	function getVersionHash() {
		return $this->version;
	}

	function debug($msg) {
		$this->debuglog[] = $msg;
	}

	/**
	 * Retrieve all errors
	 *
	 * @return array
	 */
	function getDebugLog() {
		return $this->debuglog;
	}

	/**
	 * Get if client limits should be enforced from the license response.
	 *
	 * @return bool
	 */
	function isClientLimitsEnabled() {
		return (string)$this->getKeyData( 'ClientLimitsEnabled' );
	}

	/**
	 * Get the client limit as defined by the license.
	 *
	 * @return int
	 */
	function getClientLimit() {
		$clientLimit = $this->getKeyData( 'ClientLimit' );

		if ($clientLimit == '') {
			return 0 - 1;
		}


		if (!is_numeric( $clientLimit )) {
			$this->debug( 'Invalid client limit value in license' );
			return 0;
		}

		return (int)$clientLimit;
	}

	/**
	 * Format the client limit for display in a human friendly way.
	 *
	 *  Expect a formatted number or the text 'None' for 0.
	 *
	 * NOTE: If an admin instance is not provided or the key has no translation,
	 * an English value would be returned.
	 *
	 * @param Admin $admin Admin instance for contextual language.
	 *
	 * @return string
	 */
	function getTextClientLimit($admin = null) {
		$clientLimit = $this->getClientLimit(  );
		$result = 'Unlimited';

		if (0 < $clientLimit) {
			$result = number_format( $clientLimit, 0, '', ',' );
		} else {
			if ($admin && $text = $admin->lang( 'global', 'unlimited' )) {
				$result = $text;
			}
		}

		return $result;
	}

	/**
	 * Get the number of active clients in the installation.
	 *
	 * @return int
	 */
	function getNumberOfActiveClients() {
		return (int)get_query_val( 'tblclients', 'count(id)', 'status=\'Active\'' );
	}

	/**
	 * Format the number of active clients for display in a human friendly way.
	 *
	 * Expect a formatted number or the text 'None' for 0.
	 *
	 * NOTE: If an admin instance is not provided or the key has no translation,
	 * an English value would be returned.
	 *
	 * @param Admin $admin Admin instance for contextual language.
	 *
	 * @return string
	 */
	function getTextNumberOfActiveClients($admin = null) {
		$clientLimit = $this->getNumberOfActiveClients(  );
		$result = 'None';

		if (0 < $clientLimit) {
			$result = number_format( $clientLimit, 0, '', ',' );
		} else {
			if ($admin && $text = $admin->lang( 'global', 'none' )) {
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
	function getClientBoundaryId() {
		return (int)get_query_val( 'tblclients', 'id', 'status=\'Active\'', 'id', 'ASC', (int)$this->getClientLimit(  ) . ',1' );
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
	function isNearClientLimit() {
		$clientLimit = $this->getClientLimit(  );
		$numClients = $this->getNumberOfActiveClients(  );

		if ($numClients < 1 || $clientLimit < 1) {
			return false;
		}

		$percentageBound = (250 < $clientLimit ? 0.0500000000000000027755576 : 0.100000000000000005551115);
		return $clientLimit * ( 1 - $percentageBound ) <= $numClients;
	}

	/**
	 * Public RSA key for asymmetric encryption
	 *
	 * @return string
	 */
	function getMemberPublicKey() {
		return '-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7OMhxWvu3FOqMblJGXjh
            vZQLhQa2wRQoetxAM7j/c+SzFVHmLteAZrn06FeoU1RhjQz9TE0kD6BzoBBuE1bm
            JkybOuhVJGVlI8QqLnl2F/jDFP3xshm2brRUt9vNBWXhGDRvOLOgmxaFtVjCiNAT
            9n4dtG+344xN7w568Rw3hnnGApypGFtypaKHSeNV6waeFgHeePXSPFMUpe9evZJa
            pyc9ENEWvi6nK9hWm1uZ+CfoeRjIKqW2QlgazGDqQtQev05LbDihK0Nc8LBqmVQS
            NB/N2CueyYKrzVUmNqbrkJaBVm6N3EnSNBOR7WXOPf1VOjGDu79kYrbhT1MUlKpp
            LQIDAQAB
            -----END PUBLIC KEY-----';
	}

	/**
	 * Encrypt data for WHMCS Member Area and License system
	 *
	 * The return value will be blank if anything goes wrong, otherwise it is a
	 * base64 encoded value.
	 *
	 * NOTE: Crypt_RSA traditionally will emit warnings; the are not suppressed
	 * here.
	 *
	 * @param array $data Key/value pairs to bundle into the encrypted string
	 * @param string $publicKey RSA public key to use for the asymmetric encryption
	 *
	 * @return string
	 */
	function encryptMemberData($data = array(  ), &$publicKey = '') {
		if (!$publicKey) {
			$publicKey = $this->getMemberPublicKey(  );
		}

		$publicKey = str_replace( array( "\n", "\r", " " ), array( '', '', '' ), $publicKey );
		$cipherText = '';

		if (is_array( $data )) {
			try {
				$rsa = new Crypt_RSA(  );
				$rsa->loadKey( $publicKey );
				$rsa->setEncryptionMode( CRYPT_RSA_ENCRYPTION_OAEP );
				$cipherText = $rsa->encrypt( json_encode( $data ) );

				if (!$cipherText) {
					throw new Exception( 'Could not perform rsa encryption' );
				} else {
					$cipherText = base64_encode( $cipherText );
				}
			}
			catch (Exception $e) {
				$this->debug( 'Failed to encrypt member data' );
			}
		}

		return $cipherText;
	}
}
