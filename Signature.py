import pickle
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from Cryptodome.Hash import keccak

class KeyManager:
    def __init__(self,private_key = None,path_to_key = None,password = None,initialize = False):
        empty = False
        if private_key == None and path_to_key == None and initialize == False:
            empty = True
        if private_key != None and path_to_key == None and initialize == False:
            self.private_key = private_key
        elif path_to_key != None and private_key == None and initialize == False:
            self.private_key = self.load_private_key(path_to_key,password)
        elif initialize != False and path_to_key == None and private_key == None:
            self.private_key = self.generate_key()     
        if not empty:
            self.public = self.private_key.public_key()
    def generate_key(self):
        private = ec.generate_private_key(ec.SECP256K1)
        return private
    def sign(self,message):
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(bytes(message,'utf-8'))
        data = hasher.finalize()
        signature = self.private_key.sign(
            data,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            )
        return signature

    def verify(self,signature,message,public_key = None):
        if isinstance(public_key,bytes):
            public_key = self.load_public_key(key=public_key)
        else:
            public_key = public_key
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
    def load_private_key(self,path_to_key,password = None):
        path = path_to_key
        try:
            pas = bytes(password,'utf-8')
        except:
            pas = password
        with open(path,  "rb" )as key_file:
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
        if path_to_file != None:
            with open(path_to_file,'wb') as key_file:
                pickle.dump(private_key,key_file)
        return private_key
    def serialize_public_key(self,path_to_file = None):
        serialized_publickey = self.public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if path_to_file != None:
            with open(path_to_file,'wb') as key_file:
                pickle.dump(serialized_publickey,key_file)
        return serialized_publickey
    
    def load_public_key(self,path_to_key = None,key = None):
        if path_to_key != None:
            path = path_to_key
            with open(path,  "rb" )as key_file:
                data = pickle.load(key_file)
                public_key = serialization.load_pem_public_key(
                data,
                )
        elif key != None:
            public_key = serialization.load_pem_public_key(
                key,
                )
        else:
            public_key = self.public
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
    y = KeyManager()
    # new = KeyManager(initialize=True)
    new = KeyManager(path_to_key='privatekey.pem',password='saboor')
    print('keymanager made')
    prk = new.serialize_private_key(path_to_file='privatekey.pem',password='saboor')
    print('private key serialized')
    puk = new.serialize_public_key(path_to_file='publickey.pem')
    print('public key serialized')
    loaded_puk = new.load_public_key('publickey.pem')
    print('loaded public key')
    new.load_private_key(path_to_key='privatekey.pem',password='saboor')
    print('loaded private key from file')
    mess = 'hello'
    signature_mes = new.sign(mess)
    print('message signed')
    corrupt_signature = signature_mes + b'hello'
    if new.verify(signature_mes,'hello',public_key=loaded_puk):
        print('signature verified')
    else:
        print('signature invalid')
    new.genrate_walletid()

