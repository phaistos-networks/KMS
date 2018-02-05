Almost all such systems use symmetic encryption(exception is Azure Keys Vault), and acceptd keys size is very conservative(very low), that's because practically
it's all about storing wrapped keys (i.e the "secret" they encrypt, and store, is the data wrapping key).
So for Google KMS
	1. Application creates a new key is generated for entity A, to be used for enc/dec all data of entity A
	2. entity's data are encrypted with that just created key
	2. KMS is asked to create a key for that entity (which will be the wrapping key)
	3. KMS is asked to encrypt the key of entity A, and it will do so using the key created for that user on KMS(the wrapping key). 
	4. KMS returns the wrapped key
	5. The application stores the encrypted entity data together with the wrapped key KMS provided us with

	To access entity data
	1. KMS is asked to unwrap the wrapped key for entity A (see /decrypt or /unwrap)
	2. KMS uses the wrapping key for that entity to decrypt the wrapped key
	3. KMS returns the unwrapped key(which is the entity data key, as the plaintext in the response)
	4. Application uses the entity data key to decrypt the entity data


It's vital that the keys themselves are **NEVER** sent to any application. KMS is the sole owner of all created(or, provided -- see later) keys/secrets
It uses its own encryption scheme to encryp and decrypt them, and it only stores to, potentially untrustworthy, backing stores

As far as keys management systems are concerned, those are secrets(i.e the wrapped keys), or are otherwise treated as secrets.
---
The only real difference between what we need, is that instead of asking KMS to create a wrapping key for an entity (i.e the wrapping
key is NOT created by the application), the application, after it has created the entity data key, it also creates the wrapping key, which
then later hands of to KMS. Like so
	1. Application creates a new key is generated for entity A, to be used for enc/dec all data of entity A
	2. Application creates a wrapping key for the entity data
	3. Application wraps(encrypt) the data key with the wrapping key to produce the wrapped key and forgets the data key
	4. Application asks KMS to associate entity with the wrapping key it provides it with. See `set_keys`
	5. Application encrypts entity's data that just created key(daata key)
	5. Application stores the encrypted entity data together with the wrapped key

---
# KEYS API
The entity, or object id, is for all intents&purproses the key name.
To that end, we need two support these methods:

##`create_keys`
For each provided key name, KMS will create a new key(i.e a wrapping key), and will store it, encrypted with its own encryption key to the backing store

## `set_keys`
For each provided pair of (key name, key), KMS will encrypt the store the provided key(i.e the wrapping key) encrypted with its own encryption key to the backing store

##`encrypt` (aliased as `wrap`)
For each provided pair of (key name, plaintext), KMS will retrieve the respctive encrypted key by name, decrypt it using its own key, and then use that to encrypt the plain text and return the ciphertext back

## `decrypt`
For each provided pair (key name, ciphertext), KMS will retrieve its decryption key(created using either `create_keys` or `set_keys`), decrypt the cipherext and return the plaintext
If this is an unwrap operation, the ciphertext would be the wrapped key(i.e the encrypted data key), and the decrypted plaintext would be the data key, which the application can use the decrypt an entity's data.

## `unwrap`
Similar semantics to decrypt, except that multiple (key name, ciphertext) can be specified, and the response is made up of (key name, plaintext), wheras decrypt's response is the plaintext of the ciphertext for the single key requested

## `delete_keys`
One key name per line


# SEECRETS API
In addition to storing keys in a keysring, identified by a name, we will also support secrets. The data model will approximate Vault's, where each secret is associated with 0+ (name, value) properties. 
Secrets will be stored elsewhere and will also be encrypted using KMS encryption key.

## `set_secrets`
For each provided pair (secret name, [(name, value)), we will store one row for each (secret name, propery name) and the value will be the encrypted value of the property, using the KMS encryptin key
If the value is empty, the secret property will be deleted.
lines of (secret/key name, SPACE, list of (property name:str,=,property value:base64)


## `get_secrets`
For each provides pair (secret name, [property name]), we will return all properties associated with that secret. If the list of properties is empty, all secrets will be returned



# Authentication API


# System API
## `seal`

## `unseal`

----
There is a subtle difference between keys and secrets, and wrapping/unwrapping.
Vault is managing secrets. It can store secrets on the client's behalf, and send them back when requested. 
It does NOT encrypt NOR decrypt aribtary plaintext/ciphertext provided by the applications. It can only STORE and RETURN secrets.
This is great for e.g storing passwords, certificates, etc. It can store keys as well, but the catch is, if you want to use those keys to encrypt/decrypt
you will need KMS to send them to you and you in turn would perform the encryption/decryption. ITW, the key leaves the scope of KMS.

Managing keys instead of secret means that KMS can create keys for you, and store them, and that you can ask it to encrypt arbitrary plaintext and decrypt arbitrary ciphertext content.
Vault, again, doesn't provide this kind of functionality.

The subtle difference between managing keys and supporting wrapping/unwrapping operations is that, according to my understanding of Google KMS operation for the Google Cloud Apps Suite, it's beneficial to send the wrapping key(i.e the secret) to KMS instead of creating it in the application and then retrieving it, but it's otherwise the same idea(the wrapping key is the key KMS only controls, and the plaintext sent to KMS to unwrap is the entity data wrapped key)


# TERMINOLOGY
objid, object id, and key name are used intercheably
