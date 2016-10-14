#!/bin/bash

PARAM_CONFIG="-config openssl.cnf"
PARAM_KEY="-nodes"
PARAM_SIGN=

#
# Create a self signes root certificate including a key (valid 10 years)
#
openssl req $PARAM_CONFIG -new -x509 -sha256 -newkey rsa:4096 -keyout root-key.pem $PARAM_KEY -days 3650 -out root-cert.pem -subj "/C=AT/O=Test Organisation/CN=TestCA root certificate"


# -x509 .................. output a x509 structure
# -sha256 ................ sign with hash algorythm SHA256
# -newkey rsa:4096 ....... Generate a key of type RSA with a length of 4096 bits
# -set_serial 01 ......... Serial number to use for a certificate generated
# -days 3650 ............. number of days a certificate generated is valid for 
# -keyout root-key.pem ... The output file for the generated key
# -out root-cert.pem ..... The output file for the generated certificate

#
# To check the certificate content ... 
#
#openssl x509 -text -noout -in root-cert.pem



#
# Create a first Intermediat certificate (8 years)
#

# Create the Certificate Signing Request (CSR)
openssl req $PARAM_CONFIG -new -sha256 -newkey rsa:4096 -keyout intermediateA-key.pem $PARAM_KEY -out intermediateA-csr.pem -subj "/C=AT/O=Test Organisation/CN=TestCA intermediate A certificate"

# Create the signed certificate from the CSR (8 years)
openssl ca -batch -cert root-cert.pem -keyfile root-key.pem $PARAM_CONFIG -extensions v3_ca -days 2920 -out intermediateA-cert.pem -in intermediateA-csr.pem


exit 0


#
# Create a second Intermediat certificate (6 years)
#

# Create the Certificate Signing Request (CSR)
openssl req $PARAM_CONFIG -new -sha256 -newkey rsa:4096 -keyout intermediateB-key.pem $PARAM_KEY -out intermediateB-csr.pem -subj "/C=AT/O=Test Organisation/CN=TestCA intermediate B certificate"

# Create the signed certificate from the CSR (6 years)
openssl x509 -req -sha256 -CA intermediateA-cert.pem -CAkey intermediateA-key.pem $PARAM_CONFIG -extensions v3_ca -days 2190 -out intermediateB-cert.pem -in intermediateB-csr.pem -CAcreateserial


#
# Create an website certificate (2 years) - www.example.com
#

# Create the Certificate Signing Request (CSR)
openssl req $PARAM_CONFIG -new -sha256 -newkey rsa:4096 -keyout www_example_com-key.pem $PARAM_KEY -out www_example_com-csr.pem -subj "/C=AT/O=Customer Organisation/CN=www.example.com"

# Create the signed certificate from the CSR (2 years)
openssl x509 -req -sha256 -CA intermediateB-cert.pem -CAkey intermediateB-key.pem -days 712 -out www_example_com-cert.pem -in www_example_com-csr.pem -CAcreateserial


#
# Create an website certificate (2 years) - www.example.org
#

# Create the Certificate Signing Request (CSR)
openssl req $PARAM_CONFIG -new -sha256 -newkey rsa:4096 -keyout www_example_org-key.pem $PARAM_KEY -out www_example_org-csr.pem -subj "/C=AT/O=Customer Organisation/CN=www.example.org"

# Create the signed certificate from the CSR (2 years)
openssl x509 -req -sha256 -CA intermediateB-cert.pem -CAkey intermediateB-key.pem -days 712 -out www_example_org-cert.pem -in www_example_org-csr.pem -CAcreateserial


# XXXXX










