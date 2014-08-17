<?php
/**
 * 	Tiny Tiny RSS plugin for LDAP authentication
 * 	@author Stormbyte (nawalhof@itnature.nl)
 * 	Requires php5-ldap
 * 	@version 0.02
 * 
 */
 
/**
 *  Configuration
 *
 * 	define('LDAP_AUTH_SERVER_URI', 'ldaps://LDAPServerHostname:port/');
 * 	define('LDAP_AUTH_BASEDN', 'dc=example,dc=com');
 * 	define('LDAP_AUTH_BINDDN', 'cn=serviceaccount,dc=example,dc=com');
 * 	define('LDAP_AUTH_BINDPW', 'ServiceAccountsPassword');
 * 	
 * 	Load a Filter that holds all available members
 * 	define('LDAP_AUTH_SEARCHFILTER', '(memberof=CN=TTrss,CN=Users,DC=example,DC=com)');
 *    
 */

/**
 * 	Notes -
 * 	LDAP configuration tested on Zentyal 3.5 Samba LDAP server.
 * 	The userlist is cached but the password is always validated against LDAP server
 * 
 * 	ToDo - 
 * 	Fix owner 2 hardcoded
 * 
 */
class Auth_Ldap_Php5 extends Plugin implements IAuthModule {

	private $host;
	private $base;
	private $dbh;
	private $storage = array();
	private $serverUri = null,
			$bindDN = null,
			$bindPW = null,
			$baseDN = null,
			$searchFilter = null,
			$userDN = null,
			$userDisplayName = null,
			$userMail = null,
			$ldapConnection = null;
			    
	function init($host) {
		$this->host = $host;
		$host->add_hook($host::HOOK_AUTH_USER, $this);
		
		$this->base = new Auth_Base();
		$this->owner_uid = '2'; // Owner of the LDAP data
		$this->dbh = $host->get_dbh();
		$this->load_data();
		
		$this->serverUri 	= (defined('LDAP_AUTH_SERVER_URI'))?LDAP_AUTH_SERVER_URI:null;
        $this->bindDN 		= (defined('LDAP_AUTH_BINDDN'))?LDAP_AUTH_BINDDN:null;
        $this->bindPW 		= (defined('LDAP_AUTH_BINDPW'))?LDAP_AUTH_BINDPW:null;
        $this->baseDN 		= (defined('LDAP_AUTH_BASEDN'))?LDAP_AUTH_BASEDN:null;
        
        $this->searchFilter = (defined('LDAP_AUTH_SEARCHFILTER'))?LDAP_AUTH_SEARCHFILTER:null;
	}

	function about() {
		return array(0.02, 
			"Authenticate against LDAP server", 
			"Stormbyte", 
			true);
	}

	/**
	 * 
	 * Authenticate user
	 * 
	 */
	function authenticate($login, $password) {
		if ($login && $password) {
	        // Connect to LDAP
	        if( $this->openLdap() ){
		        // Check if User is in list
		        if( $this->searchLdapUser( $login ) ){
		        	// Check if User and password are valid
			        if( $this->userDN && $this->validateLdapUser( $password ) ){
			        	// If user is valid
			        	$this->closeLdap();
						
						// Prefix userlogin not possible with api
						// $login = 'ldapuser_'.$login;
						
						$user_id = $this->base->auto_create_user($login, $password);
						
						if ($user_id) {
                    		// update user name
                    		if ($this->userDisplayName){
                    			$this->userDisplayName = db_escape_string($this->userDisplayName);
                    			db_query("UPDATE ttrss_users SET full_name = '".$this->userDisplayName."' WHERE id = " . $user_id);
                    		}
                    		// update user mail
                    		if ($this->userMail){
                    			$this->userMail = db_escape_string($this->userMail);
                    			db_query("UPDATE ttrss_users SET email = '".$this->userMail."' WHERE id = " . $user_id);
                    		}
                    		
    			        	return $user_id;
						}
			        }
		        }
	        }
			$this->closeLdap();
		}
		return false;
	}
	
	/**
	 * 
	 * Find the user that tries to login by searching the entire group.
	 * Save the entire group of users in cache.
	 * Lifetime of the LDAP cache is 5 min to prevent flooding requests to LDAP server.
	 * 
	 * If your is found in list then set user DN
	 * 
	 */
	private function searchLdapUser( $user ){
		$ldapSearchResult = $this->get( $this, 'auth_ldap_result', null );
		
		if( ( $this->get( $this, 'auth_ldap_time', 0 ) + 300 ) < time() || !$ldapSearchResult ){
			if($this->ldapConnection){
				$ldapBind = @ldap_bind( $this->ldapConnection, $this->bindDN , $this->bindPW );
				if( $ldapBind ){
					// performing search
					$ldapSearch = @ldap_search( $this->ldapConnection, $this->baseDN, $this->searchFilter );
					$ldapSearchResult = $this->processLdapResult( ldap_get_entries( $this->ldapConnection, $ldapSearch ) );
					$this->set($this, 'auth_ldap_time', time(), false );
					$this->set($this, 'auth_ldap_result',  $ldapSearchResult, true );
				}
			}
		}
		
		if( $ldapSearchResult && isset($ldapSearchResult[$user])){
			$this->userDN = $ldapSearchResult[$user]['dn'];
			$this->userDisplayName = $ldapSearchResult[$user]['displayname'];
			$this->userMail = $ldapSearchResult[$user]['mail'];
			return true;
		}
		
		return false;
	}
	
	/**
	 * 
	 * The LDAP result will be filtered so it returns only data we need.
	 * 
	 */
	private function processLdapResult( $ldapSearchResult ){
		$result = array();
		if( $ldapSearchResult && $ldapSearchResult['count'] ){
			for( $i = 0; $i < $ldapSearchResult['count']; $i++ ){
				$newAccount = array();
				$newAccount['samaccountname'] = $ldapSearchResult[$i]['samaccountname'][0];
				$newAccount['dn'] = $ldapSearchResult[$i]['dn'];
				$newAccount['displayname'] = $ldapSearchResult[$i]['displayname'][0];
				$newAccount['mail'] = $ldapSearchResult[$i]['mail'][0];
				$result[$ldapSearchResult[$i]['samaccountname'][0]] = $newAccount;
			}
		}
		return $result;
	}
	
	/**
	 * 
	 * Check if user can be logged in with own CN and given Password.
	 * 
	 */
	private function validateLdapUser( $password ){
		if( $this->ldapConnection && $this->userDN ){
            $validateUser = ldap_bind($this->ldapConnection, $this->userDN , $password);
		    if( $validateUser ){
		    	return true;
		    }
		}
	    return false;
	}
	
	/**
	 * 
	 * Open Ldap connection
	 * 
	 */
	private function openLdap(){
		if( !$this->ldapConnection && $this->serverUri){
			$this->ldapConnection = @ldap_connect($this->serverUri);
			ldap_set_option($this->ldapConnection, LDAP_OPT_PROTOCOL_VERSION,3);
            ldap_set_option($this->ldapConnection, LDAP_OPT_REFERRALS,0);
            if( !ldap_errno($this->ldapConnection) == 0 ){
                $this->closeLdap();
            }
		}
		return $this->ldapConnection;
	}
	
	/**
	 * 
	 * Close Ldap connection
	 * 
	 */
	private function closeLdap(){
		if( $this->ldapConnection ){
			ldap_close( $this->ldapConnection );
		}
		$this->ldapConnection = null;
	}

	function api_version() {
		return 2;
	}
	
	/**
	 * Saving data from pluginhosts.php
	 * 
	 */

	function load_data($force = false) {
		if ($this->owner_uid)  {
			$result = $this->dbh->query("SELECT name, content FROM ttrss_plugin_storage
				WHERE owner_uid = '".$this->owner_uid."'");

			while ($line = $this->dbh->fetch_assoc($result)) {
				$this->storage[$line["name"]] = unserialize($line["content"]);
			}
		}
	}
	
	private function save_data($plugin) {
		if ($this->owner_uid) {
			$plugin = $this->dbh->escape_string($plugin);

			$this->dbh->query("BEGIN");

			$result = $this->dbh->query("SELECT id FROM ttrss_plugin_storage WHERE
				owner_uid= '".$this->owner_uid."' AND name = '$plugin'");

			if (!isset($this->storage[$plugin]))
				$this->storage[$plugin] = array();

			$content = $this->dbh->escape_string(serialize($this->storage[$plugin]),
				false);

			if ($this->dbh->num_rows($result) != 0) {
				$this->dbh->query("UPDATE ttrss_plugin_storage SET content = '$content'
					WHERE owner_uid= '".$this->owner_uid."' AND name = '$plugin'");

			} else {
				$this->dbh->query("INSERT INTO ttrss_plugin_storage
					(name,owner_uid,content) VALUES
					('$plugin','".$this->owner_uid."','$content')");
			}

			$this->dbh->query("COMMIT");
		}
	}

	function set($sender, $name, $value, $sync = true) {
		$idx = get_class($sender);

		if (!isset($this->storage[$idx]))
			$this->storage[$idx] = array();

		$this->storage[$idx][$name] = $value;

		if ($sync) $this->save_data(get_class($sender));
	}
	
	function get($sender, $name, $default_value = false) {
		$idx = get_class($sender);

		if (isset($this->storage[$idx][$name])) {
			return $this->storage[$idx][$name];
		} else {
			return $default_value;
		}
	}
}

?>