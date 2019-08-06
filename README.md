# datatx-geode-ldap-security # 
The datatx-geode-ldap-security project provides user security for Geode using LDAP for user authentication and authorization. Geode authorization requires LDAP groups to be created and assigned to a user to determine the user authorization rights. 

# Security Properties ##

### Client Properties - gfsecurity.properties ###

security-client-auth-init=datatx.geode.security.UserPasswordAuthInit.create   
security-username   
security-password   

### Locator/Server Properties - gfsecurity.properties ###

security-manager=datatx.geode.security.LdapUserSecurityManager
security-peer=true
security-username=peer
security-password=
security-log-file=security.log 
security-log-level=CONFIG
security-encryption-key - This is the master key for encypting and decrypting user passwords in the event UAA/Credhub is not used and user passwords are encrypted.   
security-enable-oaa-credhub -  A boolean (true/false) setting if UAA and Credhub services are used for security.   
security-uaa-url - The URL of the server hosting UAA service.    
security-uaa-entity - The UAA services entities.  
security-credhub-url - The URL of the server hosting the Credhub service.     
security-ldap-usessl - A boolean (true/false) indicating if the LDAP connection uses SSL
security-ldap-server - The LDAP server name and port [server:port]
security-ldap-basedn - The base distingushed name used for user authentication and authorization.
security-ldapSearchGroup - The LDAP object components that make up the the group's common name (cn).
security-ldapGemfireAuthorizationQuery - LDAP query for obtaining user authorization roles.
security-credentials-refresh - This time in minutes before cached user credentials are refreshed.    
security-ldap-group-separator - A character used to separate the LDAP group names defined for user authorization.
security-ldap-group-template - The template for the LDAP authorization group names used to define a user roles.   

## Generic Unbounded Docker LDAP ##

After downloading the Github project, navigate to the location of where the git repository was downloaded and go to directory **ldap** in the datatx-geode-ldap-security project.

**Build the Docker Image**

docker build -t "ldap:latest" -f Dockerfile .

**Start the Docker Image**

docker run -t -d -p 389:389  ldap:latest

**SSH to the Docker Image**

docker exec -it ed92769117e8  /bin/bash

## LDAP Configuration ##
A generic LDAP configuration file is provided. When the docker container is started, the generic-ldap.ldif file is copied to the container in the /opt/unboundid-ldap/ directory.

Below is an excert of the generic-ldap.ldif configuration fuile

**generic-ldap.ldif**

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

** User Definition**

dn: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com   
objectClass: top   
objectClass: inetOrgPerson   
uid: uTestClusterAll   
cn: uTestClusterAll   
userPassword: password   

**User Group Definition**

dn: cn=GEODE-APP1-TEST-CLUSTER-A,ou=group,ou=corporate,dc=customer,dc=com
objectClass: groupOfUniqueNames
objectClass: top
ou: group
uniquemember: cn=uTestClusterAll,ou=people,ou=corporate,dc=customer,dc=com
cn: GEODE-APP1-TEST-CLUSTER-A

## LDAP Viewer ##

Download Apache Directory Studio from http://directory.apache.org/studio
to view the LDAP configuration. 

## LDAP Authorization Groups ##

{APPL}-GF-{ENV}-CLSTR-ADMIN-RWM
{APPL}-GF-{ENV}-CLSTR-ADMIN-R
{APPL}-GF-{ENV}-CLSTR-ADMIN-W
{APPL}-GF-{ENV}-CLSTR-ADMIN-M

{APPL}-GF-{ENV}-DATA-ADMIN-M

{APPL}-GF-{ENV}-CLSTR-USER-RWM
{APPL}-GF-{ENV}-CLSTR-USER-R
{APPL}-GF-{ENV}-CLSTR-USER-W
{APPL}-GF-{ENV}-CLSTR-USER-M

{APPL}-GF-{ENV}-DATA-USER-RW-{REGION}
{APPL}-GF-{ENV}-DATA-USER-R-{REGION}
{APPL}-GF-{ENV}-DATA-USER-W-{REGION}

## Scripts ##

decrypt.sh   
encrypt.sh   


## UAA/Credhub ##

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
