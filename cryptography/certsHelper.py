
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import backend
import datetime
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.extensions import Extension
from cryptography.x509 import UnrecognizedExtension
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import binascii

class LoadCert(object):
    
    def __init__(self,filename,mode='der'):
        
        self.fname=filename
        self.mode=mode 
    def readcert(self):
        if self.mode in ['der','bin']:
            crt=self._readder()
            return crt
        elif self.mode in ['crt','pem','cert']:
            crt=self._readpem()
            return crt

    def _readder(self):
        with open(self.fname, "r") as f:
            pemdata=f.read()          
        cert = x509.load_der_x509_certificate(pemdata, default_backend())
        return cert
    
    def _readpem(self):
        with open(self.fname, "r") as f:
            pemdata=f.read()          
        cert = x509.load_pem_x509_certificate(pemdata, default_backend())
        return cert
    
class MakeCert(object):
    
    def __init__(self,name,ca=False,ksize=2048,write_to_disk=True,directory=None,issuer={"2.5.4.6":'US',"2.5.4.8":'NJ',"2.5.4.7":'Mahwah',"2.5.4.10":'Radware',"2.5.4.3":'RadwareCACert'},subject={'CoN':'US','SN':'NJ','LN':'Mahwah','ON':'Radware','CN':'RadwareCert'},sign_key='',sign_pubkey=None,sign_key_pswd=None):
        self.name=name
        self.ca=ca
        self.ksize=ksize
        self.wrt=write_to_disk
        self.dir=directory
        self.sign_key=sign_key
        self.sign_key_pswd=sign_key_pswd
        self.issuer={x:issuer[x].decode('utf-8') for x in issuer}
        self.subject={x:subject[x].decode('utf-8') for x in subject}
        
                
        if sign_pubkey:
            issuercrt=LoadCert(filename=sign_pubkey, mode ='crt').readcert()
            for a in issuercrt.subject:
                self.issuer[str(a.oid.dotted_string)]=a.value
        
        self.certbuildattr()

        if self.wrt:
            if not self.dir:
                print 'filename for write to disk not provided, writing to local directory'
                self.dir='' 
                
    def makecert(self):
        self._makecert()
        
    def certbuildattr(self):

        self.serial=x509.random_serial_number()
        self.notvalidbefore=datetime.datetime.utcnow()
        self.notvalidafter=datetime.datetime.utcnow()+datetime.timedelta(days=650)
        self.extls=[]
    
    def _makecert(self):
        keymycert = rsa.generate_private_key(public_exponent=65537,key_size=self.ksize,backend=default_backend())


        with open(self.dir+self.name+'_priv_key.pem', "wb") as f:
            f.write(keymycert.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(b"admin"),))

        with open(self.dir+self.name+'_clear_priv_key.pem', "wb") as f:
            f.write(keymycert.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption(),))   

        issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,self.issuer["2.5.4.6"]),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,self.issuer["2.5.4.8"]),x509.NameAttribute(NameOID.LOCALITY_NAME,self.issuer["2.5.4.7"]),x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.issuer["2.5.4.10"]),x509.NameAttribute(NameOID.COMMON_NAME, self.issuer["2.5.4.3"]),])
        
        with open(self.sign_key, "r") as f:
          
            pemdata=f.read()
    
        signkey = load_pem_private_key(data=pemdata,password=self.sign_key_pswd,backend=default_backend())
        
        certsubject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,self.subject['CoN']),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,self.subject['SN']),x509.NameAttribute(NameOID.LOCALITY_NAME,self.subject['LN']),x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.subject['ON']),x509.NameAttribute(NameOID.COMMON_NAME, self.subject['CN']),])

#        self.cert = x509.CertificateBuilder().subject_name(certsubject).issuer_name(issuer).public_key(keyo.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=650)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"ocert")]),critical=False,).sign(rootkey,hashes.SHA256(),default_backend())
        self.cert = x509.CertificateBuilder(issuer,certsubject,keymycert.public_key(),self.serial,self.notvalidbefore,self.notvalidafter,self.extls)
        self.cert=self.cert.sign(signkey,hashes.SHA256(),default_backend())

        with open(self.dir+self.name+'_public_key.pem', "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        
class CopyCert(object):
    
    def __init__(self,name,ca=False,ksize=2048,write_to_disk=True,directory=None,issuer={"2.5.4.6":'US',"2.5.4.8":'NJ',"2.5.4.7":'Mahwah',"2.5.4.10":'Radware',"2.5.4.3":'RadwareCACert'},cert_to_copy=None,sign_key='',sign_pubkey=None,sign_key_pswd=None, skip_oids=[]):
        self.name=name
        self.ca=ca
        self.ksize=ksize
        self.wrt=write_to_disk
        self.dir=directory
        self.cccert=cert_to_copy
        self.sign_key=sign_key
        self.sign_key_pswd=sign_key_pswd
        self.skip=skip_oids
        self.issuer={x:issuer[x].decode('utf-8') for x in issuer}
        
        if sign_pubkey:
            issuercrt=LoadCert(filename=sign_pubkey, mode ='crt').readcert()
            for a in issuercrt.subject:
                self.issuer[str(a.oid.dotted_string)]=a.value

        if self.wrt:
            if not self.dir:
                print 'filename for write to disk not provided, writing to local directory'
                self.dir=''    
    
    def copycert(self):
        self._copycert()
            
    def _copycert(self):
        keymycert = rsa.generate_private_key(public_exponent=65537,key_size=self.ksize,backend=default_backend())

        print self.dir+self.name
        with open(self.dir+self.name+'_priv_key.pem', "wb") as f:
            f.write(keymycert.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption(b"admin"),))

        with open(self.dir+self.name+'_clear_priv_key.pem', "wb") as f:
            f.write(keymycert.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption(),))   

        issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,self.issuer["2.5.4.6"]),x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,self.issuer["2.5.4.8"]),x509.NameAttribute(NameOID.LOCALITY_NAME,self.issuer["2.5.4.7"]),x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.issuer["2.5.4.10"]),x509.NameAttribute(NameOID.COMMON_NAME, self.issuer["2.5.4.3"]),])
        
        with open(self.sign_key, "r") as f:
          
            pemdata=f.read()
    
        signkey = load_pem_private_key(data=pemdata,password=self.sign_key_pswd,backend=default_backend())  

        self.cert=self._copyattr(keymycert,issuer,signkey)
        print self.dir+self.name
        with open(self.dir+self.name+'_public_key.pem', "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        
    def _copyattr(self,keymycert,issuer,signkey):
        dupextls=[]
        for e in self.cccert.extensions:
            if e.oid._dotted_string in self.skip:
                pass
            else:
                dupextls.append(e)
        newcert=x509.CertificateBuilder(issuer,self.cccert.subject,keymycert.public_key(),self.cccert.serial_number,self.cccert.not_valid_before,self.cccert.not_valid_after,dupextls)
        newcert= newcert.sign(signkey,hashes.SHA256(),default_backend())
        return newcert
