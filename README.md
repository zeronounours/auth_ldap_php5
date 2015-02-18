# Tiny Tiny RSS plugin for LDAP authentication

## About

__Author:__ Stormbyte (nawalhof@itnature.nl)

__Contributors:__

* zeroNounours (zeronounours@zeronounours.eu)

__Version__: 0.03

__Dependencies:__

* php5-ldap


## Configuration

Just add the following lines to Tiny Tiny RSS config file:

      // LDAP server settings
      define('LDAP_AUTH_SERVER_URI', 'ldaps://LDAPServerHostname:port/');
      define('LDAP_AUTH_BASEDN', 'dc=example,dc=com');
      define('LDAP_AUTH_BINDDN', 'cn=serviceaccount,dc=example,dc=com');
      define('LDAP_AUTH_BINDPW', 'ServiceAccountsPassword');

      // Filter to apply to limit users
      define('LDAP_AUTH_SEARCHFILTER', '(memberof=CN=TTrss,CN=Users,DC=example,DC=com)');

      // LDAP attributes mapping (in lowercase)
      define('LDAP_AUTH_UID_ATTR', 'samaccountname');   // Unique identifier: ie. login
      define('LDAP_AUTH_EMAIL_ATTR', 'mail');
      define('LDAP_AUTH_DISPLAYNAME_ATTR', 'displayname');

## Notes

LDAP configuration tested on:

* Zentyal 3.5 Samba LDAP server.
* openLDAP 2.4 server and Tiny Tiny RSS 1.15

The userlist is cached but the password is always validated against LDAP server


## ToDo

* Fix owner 2 hardcoded

