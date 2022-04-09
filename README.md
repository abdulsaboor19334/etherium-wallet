# Basic Etherium Cryptography

## Introduction 

This code uses the python **cryptography** module to genrate [Elliptic Curve](#EC) key pairs. The **KeyManager** class provides a few essential methodes that demonstrate how the key pairs are mostly used. 

## Methods 
| Method Name | Function |
| --- | --- |
| __init\_\_| the class on initiialisation takes 3 keyword arguments all of thich are optional. if no arguments are passed the class will genrate a new key. The first arguemnt is [ *private key* ](#privatekey) which can be an instance of the *_EllipticCurvePrivateKey* or a string with the path of the key both formats are supported. The password is only required if the private key is encrypted. The argument save which by default is `False` determines if the keys have to be saved when the seralize method is called |
| _genrate_key | This method as seen from the syntax is a local method which genrates a private key |
| sign | This method take one argument the *message* and returns tuple of the [digital signature](#signature) and the orignal message |
| verify | This is a [*static method*](#static_method) that takes two positional arguments first it takes a tuple with the same format as the method **sign** returns secondly it takes a [public key](#publickey) against which the message is verified |
| _load_private_key | This method takes a string argument that is the path to a file with key saved the second argument is an optional keyword argument which is needed only in case your key is encrypted |
| serialize_private_key | This method turns the python instance of the private key to a readable version that can be saved. It takes two keyword arguemnts. if the argument password is given the key will be encrypted. the argument *path_to_file* is only valid if *save* is set to `True`. In which case the key would be saved at the path specified else it would save it in the same directory. regardless of the status of save the function returns the serialized version of the key which you can use in other ways. |
| load_external_public_key | This is a static method that takes a publickey as a file and as an instance and loads the key into usable format |
| genrate_walletid | This method when called will genrate a wallet id which is complient to the EIP-55 standards for more [click](https://eips.ethereum.org/all) |
| EIP55_checksum | This genrates an EIP-55 compliant checksum for your wallet id |



### <a name="privatekey"> Private Key </a>
A private key is basically just a random number that **you and only you alone posess**! The set that the number is chosen from at random is so vast that the probability of two people ever getting the same private key is nearly non-existent.

### <a name="publickey"> Public Key</a>
A public key unlike a private key is not chosen at random. Depending on the type of asymitric key encryption you are using it is derived from the private key. **The process is only one way**. A private key cannot be derived from a public key. Due to this property a public key can be shared with anyone without the fear of exposing your private key.

#### Uses 
- In it's basic use a private key is a decryption key and a public key is an encryption key. e.g Saboor has to send Jatin a secret message. "I like pineapples on my pizza!" 
  - Saboor would take the public key that jatin has shared. 
  - He would encrypt his message using the public key. Now his message has turned into 
    "Hu&F&KJD#*KBS\$^(KNVDE$%UI&$C VNKUR%&KJJVFR%^"
  - Saboor sends this message to Jatin. 
  - Jatin uses his secret private key to decrypt the message and now he hates Saboor. 

Jatin was the only one in posession of the key! and the message could only be decrypted by that key. This ensures that the message Saboor sent is only seen by Jatin and no one else. 
- In it's second use the private key is used to genrate a digital signature which verifies the identity of the private key holder. e.g Saboor is sending a message to Jatin but he wants to confirm that the person on the other side is infact actually Jatin. <a name="signature"></a>
  - Jatin uses his **private key** to encrypt a message
  - he sends this message and the signature to Saboor
  - Saboor using Jatin's **public key** decrypts the signature.
  - If the signature is equal to the message this confirms that the signature was indeed created using Jatin's private key. Because the public key was able to decrypt it into the message.
  - In this case the keys are used for opposite purposes and for different reasons. 

### <a name="static_method">Static method </a>
These methodes are not associated with any spesific instance of a class. They are genral purpose tools related to the class or make changed to the class as a whole.
### <a name="EC"> Elliptic Curve </a> 
An elliptic curve is a smooth algebric curve with certian rules that are beyond the scope of this document. Some things you should keep in mind are that a private key is a random number greater than the genrator point at infinity denoted by **G**. A public key is the product of this genrator point with the private key along the curve it reaches a point on the curve with an x and a y value. how these values are handled and how the product of G and K (the private key) is calculated can be seen by visiting [click](https://secg.org/). 

If you are intrested in the mathematics drop me an email at abdulsaboorawan2000@gmail.com would be glad to guide you. I personally suggest, if you are diving into the blockchain world have a great understanding of basic elliptic curve cryptography and study the EIP/BIP carefully.

