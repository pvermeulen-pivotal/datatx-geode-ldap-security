#!/bin/bash
java -cp ./security/lib/* -Dsecurity-encryption-master=$1 datatx.geode.security.Encryption decrypt $2