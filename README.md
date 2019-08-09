# Geode LDAP Security # 
The Geode LDAP Security project provides user security for Geode clients and peers using LDAP for authentication and authorization. Geode performs user authentication (user name and password) and retreives LDAP groups assigned to the user for authorization rights. 

By configuring the ***security-enable-oaa-credhub*** property and setting it to true and also configuring the UAA ***security-uaa-url*** and Credhub ***security-credhub-url*** URLs and UAA ***security-uaa-entity*** entities, the LdapUserSecurityManager will first call the UAA service to obtain an access token which is used to access the Credhub service. After the access token has been obtained, a call is made to Credhub to retreive a user's credentials.

If the user credentials retreived from either properties or via Credhub, a check is made to determine if the password is encrypted. If the user password is encrypted, the LdapUserSecurityManager will decrypt the password.

Once the user name and password have been retreived and decrypted (if necessary), LdapUserSecurityManager calls the LDAP service with the user name and password to authenticate the user credentials. If the credentials are valid, the LdapUserSecurityManager will then query the LDAP service to obtain the authorization groups assigned to the user. 

After the user has been authenticated and the user authorization groups retreived, a user security principal is created with the user name, roles and last access time are cached by the LdapUserSecurityManager. 

When a user is being authenticated by LdapUserSecurityManager, it checks to see if the user security principal refresh time has not expired and if the time has not expired the cached credentials are returned in lieu of making a call to UAA and Credhub (if configured) and LDAP service. If the refresh time has expired, a call is made to UAA and Credhub (if configured), password is decrypted (if necessary) and a call is made to the LDAP service.

### Geode LDAP Security Overview ###

![Geode LDAP Security Overview](https://github.com/pvermeulen-pivotal/datatx-geode-ldap-security/blob/master/Overview.png)

### Geode LDAP Security Classes ###

| Package Name | Class Name | Description |
| ------------ | ---------- | ----------- |
| datatx.geode.security | Encryption | Performs password encryption and decryption |
| datatx.geode.security | UsernamePrincipal | Java security principal containing user name and assigned authorization roles |
| datatx.geode.security | UserPasswordAuthInit | Client authorization initialization for security properties |
| datatx.geode.security | LdapUserSecurityManager | Performs UAA/Credhub/LDAP requests for user authentication and authorization |

### Security Properties ###

#### Client Properties: gfsecurity.properties ####


| Property | Value |
| -------- | ----- |
|security-client-auth-init|datatx.geode.security.UserPasswordAuthInit.create|
|security-username| Geode User Name|
|security-password| Geode User Password |   

#### Locator/Server Properties: gfsecurity.properties ####


| Property | Value |
| -------- | ----- |
|security-manager|datatx.geode.security.LdapUserSecurityManager|
|security-peer|true|   
|security-username|peer|
|security-password|{empty}|
|security-log-file|security.log|
|security-log-level|CONFIG|
|security-encryption-key| This is the master key for encrypting and decrypting user passwords in the event UAA/Credhub is not used and user passwords are encrypted|  
|                  | Master Key - Clear Text |
|                  | file:/path/filename - Master Key in secure file | 
|security-enable-oaa-credhub|A boolean (true/false) setting if UAA and Credhub services are used for security|credentials
|security-uaa-url|The URL of the server hosting UAA service|    
|security-uaa-entity|The UAA services entities|
|security-credhub-url|The URL of the server hosting the Credhub service|
|security-ldap-usessl|A boolean (true/false) indicating if the LDAP connection uses SSL|
|security-ldap-server|The LDAP server name and port [server:port]|
|security-ldap-basedn|The base distinguished name used for user authentication and authorization|
|                    | Example: ou=people,ou=corporate,DC=customer,DC=com |
|security-ldapSearchGroup|The LDAP object components that make up the group's common name (cn)|
|                    | Example: ou=group,ou=corporate,dc=customer,dc=com |
|security-ldapGemfireAuthorizationQuery|LDAP query for obtaining user authorization roles|
|                    | Example: (&(objectclass=groupOfUniqueNames)(uniquemember=cn={0},ou=people,ou=corporate,dc=customer,dc=com)) |
|security-credentials-refresh|This time in minutes before cached user credentials are refreshed|
|security-ldap-group-separator|A character used to separate the LDAP group names defined for user authorization|
|security-ldap-group-template|The template for the LDAP authorization group names used to define a user roles|   

### Unbounded Docker LDAP ###

**Note:** ***The Unbounded Docker LDAP is used for testing only and should never be used in production***   

After downloading the datatx-geode-ldap-security Github project, navigate to the location of where the Git repository was downloaded and go to directory **ldap** in the datatx-geode-ldap-security project.

**Build the Docker Image**

This command creates a Docker image with a tag of ldap:latest and uses the Docker file in datatx-geode-ldap-security/ldap directory to create the Docker image.   
***docker build -t "ldap:latest" -f Dockerfile .***

**Start the Docker Image**

This command starts a Docker daemon container using the ldap:latest image.   
***docker run -t -d -p 389:389  ldap:latest***

**SSH to the Docker Image**

This command starts an SSH session to the Docker container. The command requires the Docker container id and to obtain the container id run the command docker ps.   
***docker exec -it ed92769117e8  /bin/bash***

### LDAP Configuration ###
A generic LDAP configuration file is provided. When the Docker container is started, the generic-ldap.ldif file is copied to the container in the /opt/unboundid-ldap/ directory.

Below is an excerpt of the generic-ldap.ldif configuration file

#### generic-ldap.ldif ####

dn: dc=customer,dc=com   
dc: customer   
objectClass: top   
objectClass: domain   

dn: ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: organizationalUnit   
ou: corporate   

dn: ou=people,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: organizationalUnit   
ou: people   

dn: ou=group,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: organizationalUnit   
ou: group   

##### **User Definition** #####

dn: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: inetOrgPerson   
uid: uTestClusterAll   
cn: uTestClusterAll   
userPassword: password   

##### **User Group Definition** #####

dn: cn=GEODE-APP1-TEST-CLUSTER-A,ou=group,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: groupOfUniqueNames   
ou: group   
uniquemember: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com   
cn: GEODE-APP1-TEST-CLUSTER-A   

### LDAP Viewer ###

To view the LDAP configuration download the Apache Directory Studio from http://directory.apache.org/studio. 

### LDAP Authorization Groups ###

LDAP authorization groups are LDAP group objects used to define the Geode authorization roles. One or more LDAP groups can be assigned to a user to create the users Geode authorization. After deciding on how the LDAP group names will be constructed in LDAP, define the security-ldap-group-template property to conform to the group naming strategy.

***security-ldap-group-template property***
**Template**: GEODE-APPLID-ENV-RESOURCE-PERMISSIONS-REGION   

The LDAP group template property defines the template used to parse the LDAP groups assigned to a user to support Geode authorizations.   

A template can be of any size and layout but each section of the template must be separated by the value defined in the ***security-ldap-separator property***. The template supports five (5) defined fields and any other combination of constant values. The five fields are listed below. The only required fields in a template is the RESOURCE and PERMISSION fields. So at the minimum the LDAP group names must define the RESOURCE and PERMISSIONS as part of the LDAP group name.

| Field Name | Description | Value | Required |
| ---------- | ----------- | ----- | -------- |
| APPLID | Application Id | User Defined | No |
| ENV | Environment | DEV | No |
|     |    | UAT |   |
|     |    | PERF |   |
|     |    | PROD |   |
| RESOURCE | Resource to secure | CLUSTER | Yes |
|          |    | DATA    |   |
| PERMISSIONS | Role Permission | R-Read | Yes |
|             |   | W-Write |   |
|             |   | M-Manage |   |
|             |   | A-All |   |
| REGION | The name of the region | Geode region name | No |

**Examples**

The following is an LDAP group name for authorizations that uses an ***-*** separator for the LDAP template components:
GEODE-APP1-TEST-CLUSTER-A [The template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS].

The following is an LDAP group name for authorizations that uses an ***-*** separator for the LDAP template components.
GEODE-APP1-TEST-DATA-RW-TestRegion [The template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS-REGION].

### Scripts ###

The following scripts are provided to encrypt and decrypt passwords. The scripts require two (2) parameters to be passed. The first parameter is the master key used to encrypt and decrypt password and the second parameter, depending on the operation, is a clear text or encrypted password.

**encrypt.sh**

    !#/bin/bash    
    java -cp ./ldap/lib/* -Dsecurity-encryption-master=$1 datatx.geode.security.Encryption encrypt $2    
   
**decrypt.sh**

    !#/bin/bash    
    java -cp ./ldap/lib/* -Dsecurity-encryption-master=$1 datatx.geode.security.Encryption decrypt $2    

### UAA/Credhub ###

Authentication via UAA is performed directly with the trusted UAA server. When successfully authenticated, the UAA server will return an access token, which must be sent to CredHub in each request. Once a token is obtained, the token  must be included in the header Authorization: Bearer [token] in your request to CredHub.

CredHub manages credentials like passwords, users, certificates, certificate authorities, ssh keys, rsa keys and arbitrary values (strings and JSON blobs). 

Credhub uses TLS encryption, so clients accessing Credhub must have a trust store containing the Credhub TLS certificate for the session to be authenticated. The LdapUserSecurityManager is configured to trust any server's certificate so a trust store is not required. This behavior is not configurable so any behavioral changes will require code changes. 

#### Start UAA/Credhub Services ####    

After downloading the datatx-geode-ldap-security Github project, navigate to the location of where the Git repository was downloaded and go to directory **credhub-uaa/docker-compose** in the datatx-geode-ldap-security project and run the Docker command below. The docker-compose up command will build the docker images and then start the containers.   

**Note:** ***The UAA/Credhub Services are used for testing only and should never be used in production***   

The docker-compose.yml file is used to create and run two Docker containers, pcfseceng/uaa and ampersand8/credhub.   

***docker-compose up***   

After the Credhub service has started, users will need to be added to the Credhub service. Run the following commands, the first command will retreive the token from the UAA service and the remaining commands call Credhub service to add the users with the UAA token.   

***Get UAA Token***   
token=$(curl -q -s -XPOST -H"Application/json" --data "client_id=credhub_client&client_secret=secret&client_id=credhub_client&grant_type=client_credentials&response_type=token" http://localhost:8081/uaa/oauth/token | jq -r .access_token)   

***Add User uTestClusterAll***   
curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterAll","type":"json","value": {"password":"password"}}' | jq .   

***Add User uTestClusterManage***   
curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterManage","type":"json","value": {"password":"password"}}' | jq .   

***Add User uTestDataAll***   
curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataAll","type":"json","value": {"password":"password"}}' | jq .   

***Add User uTestDataReadWrite***   
curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataReadWrite","type":"json","value": {"password":"password"}}' | jq .   
