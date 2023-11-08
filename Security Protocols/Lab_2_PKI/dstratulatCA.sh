#!/bin/bash

DIR="dstratulat_keys"
Green='\033[0;32m'
NC='\033[0m'
function cleanup()
{
	echo -e "${Green}[+]Clean up${NC}"
	rm $DIR/*.old

}

function init()
{
	echo $DIR	
	echo -e "${Green}[+]Genterate initial files: keys directory, index.txt and serial ${NC}"
	mkdir -p $DIR
	touch $DIR/index.txt
	echo "01" > $DIR/serial
#	echo "Update openssl.cnf file"
#	sed -i "s/^dir.*/dir\t\t= $DIR/" openssl.cnf
}

function generate_ca_key()
{

	echo -e "${Green}[+]Generate CA key${NC}"
	countryNameCA="RO"
	stateOrProvinceNameCA="B"
	localityNameCA="Bucharest"
	organizationNameCA="UPB"
	organizationalUnitNameCA="SAS"
	commonNameCA="dstratulatCA"
	
	openssl req -days 3650 -nodes -new -x509 -keyout $DIR/ca.key -out $DIR/ca.crt -config openssl.cnf -subj "/C=$countryNameCA/ST=$stateOrProvinceNameCA/L=$localityNameCA/O=$organizationNameCA/OU=$organizationalUnitNameCA/CN=$commonNameCA" 


}

function generate_server_crt()
{

	echo -e "${Green}[+]Generate server type key${NC}"
	countryNameServer="RO"
	stateOrProvinceServer="B"
	localityNameServer="Bucharest-Server"
	organizationNamServer="UPB-Server"
	organizationalUnitNameServer="SAS-Server"
	commonNameServer="server"
	emailAddressServer="server@mail.com"
	echo -e "${Green}[+]Build request${NC}"

	openssl req -nodes -new -keyout $DIR/server.key -out $DIR/server.csr -config openssl.cnf -subj "/C=$countryNameServer/ST=$stateOrProvinceNameServer/L=$localityNameServer/O=$organizationNameServer/OU=$organizationalUnitNameServer/CN=$commonNameServer/emailAddress=$emailAddressServer"

	echo -e "${Green}[+]Sign cert request with CA${NC}"
	openssl ca -days 3650 -out $DIR/server.crt -in $DIR/server.csr -extensions server -config openssl.cnf

	cleanup

}

function generate_client_crt()
{
	client=$1

	echo -e "${Green}[+]Generate client type key${NC}"
        countryNameClient="RO"
        stateOrProvinceServer="B"
        localityName="Bucharest-$client"
        organizationNamClient="UPB-$client"
        organizationalUnitNameClient="SAS-$client"
        commonNameClient="$client"
        emailAddressClient="$client@mail.com"
        echo -e "${Green}[+]Build request${NC}"

        openssl req -nodes -new -keyout $DIR/$client.key -out $DIR/$client.csr -config openssl.cnf -subj "/C=$countryNameClient/ST=$stateOrProvinceNameClient/L=$localityNameClient/O=$organizationNameClient/OU=$organizationalUnitNameClient/CN=$commonNameClient/emailAddress=$emailAddressClient"

        echo -e "${Green}[+]Sign cert request with CA${NC}"
        openssl ca -days 3650 -out $DIR/$client.crt -in $DIR/$client.csr -extensions server -config openssl.cnf

        cleanup

}

function revoke_client()
{

	client=$1
	echo -e "${Green}[+]Revoke client cert $client${NC}"
	# Revoke cert
	openssl ca -revoke $DIR/$client.crt -config openssl.cnf

	# Generate new crl
	openssl ca -gencrl -out $DIR/crl.pem -config openssl.cnf

	# Test revocation. First concatenate ca cert with newly generated crl and then verify the revocation
	cat $DIR/ca.crt $DIR/crl.pem > $DIR/revoke_test_file.pem
	openssl verify -CAfile $DIR/revoke_test_file.pem -crl_check $DIR/$client.crt

	# Delete temporary test file
	rm $DIR/revoke_test_file.pem

}




init
generate_ca_key
generate_server_crt
generate_client_crt "client"
