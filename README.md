# SampleEncDec

Steps to execute the application
================================

1. Use the below commnads to create certificates before proceed furthur.

    Create certificates at Sender side
    ----------------------------------

    1. create public and private key(key pair)

        openssl genrsa -passout pass:sender12345 -out sender.pem 2048

    2. extract the public key

        openssl rsa -in sender.pem -pubout -out sender_pub_key.pem

    3. extract the private key

        openssl pkcs8 -topk8 -inform PEM -in sender.pem -out sender_pri_key.pem -nocrypt

    4. create csr using the keypair

        openssl req -new -key sender.pem -out sender.csr

    5. To see the certificate details

        openssl req -text -in sender.csr -noout -verify

    6. To do self sign with x509

        openssl x509 -in sender.csr -out sender.crt -req -signkey sender.pem -days 3650


    Create certificates at Receiver side
    ------------------------------------

    1. create public and private key(key pair)

        openssl genrsa -passout pass:receiver12345 -out receiver.pem 2048

    2. extract the public key

        openssl rsa -in receiver.pem -pubout -out receiver_pub_key.pem

    3. extract the private key

        openssl pkcs8 -topk8 -inform PEM -in receiver.pem -out receiver_pri_key.pem -nocrypt

    4. create csr using the keypair

        openssl req -new -key receiver.pem -out receiver.csr

    5. To see the certificate details

        openssl req -text -in receiver.csr -noout -verify

    6. To do self sign with x509

        openssl x509 -in receiver.csr -out receiver.crt -req -signkey receiver.pem -days 3650

2. Place the certificates under the resources/static folder in the project.

3. Now you can run the project. 



