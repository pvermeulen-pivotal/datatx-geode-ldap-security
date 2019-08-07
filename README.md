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

After downloading the Github project, navigate to the location of where the git repository was downloaded and go to directory **ldap** in the datatx-geode-ldap-security project.

**Build the Docker Image**

docker build -t "ldap:latest" -f Dockerfile .

**Start the Docker Image**

docker run -t -d -p 389:389  ldap:latest

**SSH to the Docker Image**

docker exec -it ed92769117e8  /bin/bash

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

__**User Definition**__

dn: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: inetOrgPerson   
uid: uTestClusterAll   
cn: uTestClusterAll   
userPassword: password   

__**User Group Definition**__

dn: cn=GEODE-APP1-TEST-CLUSTER-A,ou=group,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: groupOfUniqueNames   
ou: group   
uniquemember: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com   
cn: GEODE-APP1-TEST-CLUSTER-A   

### LDAP Viewer ###

Download Apache Directory Studio from http://directory.apache.org/studio to view the LDAP configuration. 

### LDAP Authorization Groups ###

security-ldap-group-template   
Template: GEODE-APPLID-ENV-RESOURCE-PERMISSIONS-REGION   

The LDAP group template property defines the template that will be used for the user's LDAP group to support Geode authorizations. A template can be of any size and layout but each section of the template must be separated by the value defined in the security-ldap-separator property. The template can support five (5) defined fields along with other constant values. The five fields are listed below and the only required fields need in a template is the RESOURCE and PERMISSION fields.

| Field Name | Description | Required |
| ---------- | ----------- | -------- |
| APPLID | Application Id |  |
| ENV | Environment [dev,uat, prod, etc] |  |   
| RESOURCE | CLUSTER | Yes |
|          | DATA    |   |
| PERMISSIONS | R-Read | Yes |
|             | W-Write |   |
|             | M-Manage |   |
|             | A-All |   |
| REGION | Region name |   |

**Examples**

The following is an LDAP group name for authorizations that use an **-** separator the LDAP template components.
GEODE-APP1-TEST-CLUSTER-A and the template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS.

The following is an LDAP group name for authorizations that use an **-** separator the LDAP template components.
GEODE-APP1-TEST-DATA-RW-TestRegion and the template for the LDAP group would be GEODE-APPID-ENV-RESOURCE-PERMISSIONS-REGION.

### Scripts ###

decrypt.sh   
encrypt.sh   


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
