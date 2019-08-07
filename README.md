# Geode LDAP Security # 
The Geode LDAP Security project provides user security for Geode using LDAP for user authentication and authorization. Geode authorization requires LDAP groups to be created and assigned to a user to determine the user authorization rights. 

### Geode LDAP Security Overview ###

![Geode LDAP Security Overview](https://github.com/pvermeulen-pivotal/datatx-geode-ldap-security/blob/master/Overview.png)

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
|security-encryption-key| This is the master key for encypting and decrypting user passwords in the event UAA/Credhub is not used and user passwords are encrypted|   
|security-enable-oaa-credhub|A boolean (true/false) setting if UAA and Credhub services are used for security|credentials
|security-uaa-url|The URL of the server hosting UAA service|    
|security-uaa-entity|The UAA services entities|
|security-credhub-url|The URL of the server hosting the Credhub service|
|security-ldap-usessl|A boolean (true/false) indicating if the LDAP connection uses SSL|
|security-ldap-server|The LDAP server name and port [server:port]|
|security-ldap-basedn|The base distingushed name used for user authentication and authorization|
|security-ldapSearchGroup|The LDAP object components that make up the the group's common name (cn)|
|security-ldapGemfireAuthorizationQuery|LDAP query for obtaining user authorization roles|
|security-credentials-refresh|This time in minutes before cached user credentials are refreshed|
|security-ldap-group-separator|A character used to separate the LDAP group names defined for user authorization|
|security-ldap-group-template|The template for the LDAP authorization group names used to define a user roles|   

### Generic Unbounded Docker LDAP ###

After downloading the datatx-geode-ldap-security Github project, navigate to the location of where the git repository was downloaded and go to directory **ldap** in the datatx-geode-ldap-security project.

**Build the Docker Image**

This command creates a Docker image with a tag of ldap:latest and uses the Docker file in datatx-geode-ldap-security/ldap directoryto create the Docker image.   
*docker build -t "ldap:latest" -f Dockerfile .*

**Start the Docker Image**

This command starts a Docker daemon container using the ldap:latest image.   
*docker run -t -d -p 389:389  ldap:latest*

**SSH to the Docker Image**

This command starts an SSH session to the Docker container. The command requires the Docker container id and to obtain the container id run the command docker ps.   
*docker exec -it ed92769117e8  /bin/bash*

### LDAP Configuration ###
A generic LDAP configuration file is provided. When the docker container is started, the generic-ldap.ldif file is copied to the container in the /opt/unboundid-ldap/ directory.

Below is an excert of the generic-ldap.ldif configuration file

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

LDAP authorization groups are LDAP group objects that are used to define the Geode authorization roles. One or more LDAP groups can be assigned to a user to create the users Geode authorization. After deciding on how the LDAP group names will be constructed in LDAP define the security-ldap-group-template property to conform to the group naming strategy.

***security-ldap-group-template property***
**Template**: GEODE-APPLID-ENV-RESOURCE-PERMISSIONS-REGION   

The LDAP group template property defines the template used to parse the LDAP groups assigned to a user to support Geode authorizations.   

A template can be of any size and layout but each section of the template must be separated by the value defined in the *security-ldap-separator property*. The template supports five (5) defined fields and any other combination of constant values. The five fields are listed below. The only required fields required in a template is the RESOURCE and PERMISSION fields. So at the minimum the LDAP group names must define the RESOURCE and PERMISSIONS as part of the LDAP group name.

| Field Name | Description | Required |
| ---------- | ----------- | -------- |
| APPLID | Application Id |  |
| ENV | Environment |    |
|     | DEV |   |
|     | UAT |   |
|     | PERF |   |
|     | PROD |   |
| RESOURCE | CLUSTER | Yes |
|          | DATA    |   |
| PERMISSIONS | R-Read | Yes |
|             | W-Write |   |
|             | M-Manage |   |
|             | A-All |   |
| REGION | Region name |   |

**Examples**

The following is an LDAP group name for authorizations that uses an ***-*** separator for the LDAP template components:
GEODE-APP1-TEST-CLUSTER-A [The template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS].

The following is an LDAP group name for authorizations that uses an ***-*** separator for the LDAP template components.
GEODE-APP1-TEST-DATA-RW-TestRegion [The template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS-REGION].

### Scripts ###

The following scripts are provided to encrypt and decrypt passwords. The scripts require two (2) parameters to be passed to the script. The first parameter is the master key used to encrypt and decrypt password and the second parameter, depending on the operation, is a clear text or encrypted password.

encrypt.sh   
   !#/bin/bash   
   java -cp ./ldap/lib/* -Dsecurity-encryption-master=$1 datatx.geode.security.Encryption encrypt $2   
   
decrypt.sh   


### UAA/Credhub ###

Certificates

start uaa/credhub with docker-compose

C:\Develop\credhub-docker\docker-compose>docker-compose up

token=$(curl -q -s -XPOST -H"Application/json" --data "client_id=credhub_client&client_secret=secret&client_id=credhub_client&grant_type=client_credentials&response_type=token" http://localhost:8081/uaa/oauth/token | jq -r .access_token)

curl -k https://localhost:9000/api/v1/data?name=/thisissometest -H "content-type: application/json" -H "authorization: bearer ${token}" | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterManage","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataReadWrite","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdClusterAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdClusterManage","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdDataAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdDataReadWrite","type":"json","value": {"password":"password"}}' | jq .
