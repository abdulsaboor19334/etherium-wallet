import pickle
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from Cryptodome.Hash import keccak
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey , _EllipticCurvePublicKey

class KeyManager:
    def __init__(self,private_key = None,password = None,save = False):
        self.save = save
        if isinstance(private_key,_EllipticCurvePrivateKey):
            self.private_key = private_key
        elif isinstance(private_key,str):
            self.private_key = self._load_private_key(private_key,password)
        else:
            self.private_key = self._generate_key()
        self.public = self.private_key.public_key()
    def _generate_key(self):
        private = ec.generate_private_key(ec.SECP256K1)
        return private
    def sign(self,message:str) -> tuple:
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(bytes(message,'utf-8'))
        data = hasher.finalize()
        signature = self.private_key.sign(
            data,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
        return signature , message
    @staticmethod
    def verify(sig_mes,public_key) -> bool:
        if isinstance(public_key,str):
            with open(public_key,  "rb" ) as key_file:
                data = pickle.load(key_file)
                public_key = serialization.load_pem_public_key(
                data,
                )
        signature, message = sig_mes
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(bytes(message,'utf-8'))
        data = hasher.finalize()
        try:
            public_key.verify(
                signature, 
                data, 
                ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                )
            return True
        except InvalidSignature:
            return False

    def _load_private_key(self,path_to_key,password = None):
        try:
            pas = bytes(password,'utf-8')
        except:
            pas = password
        with open(path_to_key,  "rb" )as key_file:
            data = pickle.load(key_file)
            private_key = serialization.load_pem_private_key(
            data,
            password=pas
            )
        return private_key

    def serialize_private_key(self,password = None,path_to_file = None):
        if password != None:
            private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(password,'utf-8'))
            )
        elif password == None:
            private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
         )
        if self.save:
            if path_to_file == None:
                with open('privatekey.pem','wb') as key_file:
                    pickle.dump(private_key,key_file)
            else:
                with open(path_to_file,'wb') as key_file:
                    pickle.dump(private_key,key_file)
        return private_key

    def serialize_public_key(self,path_to_file = None):
        serialized_publickey = self.public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if self.save:
            if path_to_file != None:
                with open(path_to_file,'wb') as key_file:
                    pickle.dump(serialized_publickey,key_file)
            else:
                with open('publickey.pem','wb') as key_file:
                    pickle.dump(serialized_publickey,key_file)
        return serialized_publickey

    @staticmethod
    def load_external_public_key(key):
        if isinstance(key,str):
            with open(key,  "rb" )as key_file:
                data = pickle.load(key_file)
                public_key = serialization.load_pem_public_key(
                data,
                )
        elif isinstance(key,_EllipticCurvePublicKey):
            public_key = serialization.load_pem_public_key(
                key,
                )
        return public_key

    def genrate_walletid(self):
        x = hex(self.public.public_numbers().x)[2:]
        y = hex(self.public.public_numbers().y)[2:]
        k = keccak.new(digest_bits=256)
        k.update(''.join([x,y]).encode())
        return '0x' + k.hexdigest()[-40:]

    def EIP55_checksum(self):
        adress = self.genrate_walletid()[2:]
        k = keccak.new(digest_bits=256)
        k.update(adress.encode())
        compare = k.hexdigest()[-40:]
        mystr = ''
        for index,item in enumerate(adress):
            if int(item,16) > 9 and int(compare[index],16) >= 8:
                mystr += item.upper()
            else:
                mystr += item
        return mystr

if __name__ == '__main__':
    key = KeyManager(save=True)
    key.serialize_private_key(password='saboor')
    key.serialize_public_key(path_to_file='mynewkey.pem')
    x = KeyManager.load_external_public_key('publickey.pem')
    mess = 'hello'
    signature_mes = key.sign(mess)
    if KeyManager.verify(signature_mes,key.public):
        print('signature verified')
    else:
        print('signature invalid')
    # new.genrate_walletid()

