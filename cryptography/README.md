**NOTEBOOK**

Keys and Certs notebook includes recipes for creating key pair, creating certs with userdefined attributes and custom extensions, as well as various ways to sign the cert, creating root and intermediate certs and use them to sign other certs

scapy_TLS includes recipes to create TLS client/servers with granular control over TLS layers. 

---

## certsHelper Tool

- load certs from any format including from packet caps,
- create a new cert with attributes and extensions of your choosing
- copycert: copy attributes and extensions of a cert and create a new cert with those 

#### Usage  

###### Example1:

custcert=LoadCert(filename='/home/ftp/certificates/crt.crt', mode ='crt')
newcert=CopyCert('bloomcrt.crt',directory='/home/ftp/certificates/',ksize=2048,cert_to_copy=custcert.readcert(),sign_key="/home/ftp/certificates/rootCA.key").copycert()

###### Example2:

custcert=LoadCert(filename='/home/ftp/certificates/clientcert.bin')
newcert=CopyCert('chunkclient2048.crt',directory='/home/ftp/certificates/bloom/',ksize=2048,cert_to_copy=custcert.readcert(),sign_key="/home/ftp/certificates/bloom/subrootcakey4096clear.pem").copycert()

###### Example3:

newcert=MakeCert('newcert2048',directory='/home/ftp/certificates/',sign_key='/home/ftp/certificates/rootCA.key').makecert()

###### Example4:

custcert=LoadCert(filename='/home/ftp/certificates/firstcert.bin')
newcert=CopyCert('2copiedcert2048',directory='/home/ftp/certificates/',cert_to_copy=custcert.readcert(),sign_key='/home/ftp/certificates/rootCA.key', skip_oids=['1.3.6.1.4.1.11129.2.4.2']).copycert()

###### Example5:

custcert=LoadCert(filename='/home/ftp/certificates/sccm_apr21.crt', mode ='crt')    
newcert=CopyCert('sccmcpycrt',directory='/home/ftp/certificates/',cert_to_copy=custcert.readcert(),sign_key="/home/ftp/certificates/sccmcpyinter_clear_priv_key.pem", sign_pubkey="/home/ftp/certificates/sccmcpyinter_public_key.pem").copycert()

###### Example6:

custcert=LoadCert(filename='/home/ftp/certificates/server.bin', mode ='der')    
newcert=CopyCert('sccm_22server_crt',directory='/home/ftp/certificates/',cert_to_copy=custcert.readcert(),sign_key="/home/ftp/certificates/sccm_22server_inter_clear_priv_key.pem", sign_pubkey="/home/ftp/certificates/sccm_22server_inter_public_key.pem").copycert()
