#!/bin/bash

export token=$(curl -q -s -XPOST -H"Application/json" --data "client_id=credhub_client&client_secret=secret&client_id=credhub_client&grant_type=client_credentials&response_type=token" http://localhost:8081/uaa/oauth/token | jq -r .access_token)

echo "token=" $token

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestClusterManage","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uTestDataReadWrite","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdClusterAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdClusterManage","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdDataAll","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uProdDataReadWrite","type":"json","value": {"password":"password"}}' | jq .

curl -k -XPUT https://localhost:9000/api/v1/data -H "content-type: application/json" -H "authorization: bearer ${token}" -d '{"name": "/uMasterEncryption","type":"json","value": {"password":"ABCDEF0123456789"}}' | jq .
