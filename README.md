Phaistos KMS is a very simple to operate, high performance, stateless keys and secrets managements service.

- You can use KMS to create and erase keys. You can use it to encrypt plaintext and decrypt ciphertext using keys managed by KMS.
- You can use KMS for keys-wrap based encryption. You create an `entity key`, then either create a `wrapping key` yourself and ask KMS to associate it with a key, or ask KMS to create and return the wrapping key for you. You then use the wrapping key to encrypt the entity key to produce the `wrapped key`. You can then encrypt your entity data(e.g an object properties) using the entity key, and then you store the encrypted data and the wrapped key side-by-side. Later, you can retrieve the wrapping key from KMS and with it, unwrap the encrypted entity key, and then use that entity key to decrypt your encrypted data. This is how most organisations deals with encryption. It facilitates effortless keys rotation among other benefits.     
- You can use it to store, access and erase secrets.
- You can deploy as many KMS instances as it makes sense for your use case, and use a load balancer to route requests to them. KMS is stateless. The KMS nodes do not need to communicate with each other, so this works great in practice.
                                        
KMS is inspired by Google KMS, AWS KMS and Hashicorp's Vault.

## Building KMS
You need clang++ 5.0 to compile it. Just type `make` and it should build KMS in a few seconds. The KMS in this repository uses:
- https://github.com/dsprenkels/sss
- https://github.com/nlohmann/json
- https://github.com/Cyan4973/xxHash
- https://www.openssl.org/

        
        
## Keys and Secrets
A key is identified by an key identifier. A secret is identified by a secret identifier, and associated with 0 or more properties. A secret property is associated with a value.
    
        
## Operation and Requirements    
KMS requires root access. 
The KMS binary permissions must be 0700 (only owner can read, write, and execute). KMS will not run unless the permissions are correct. It also requires a certificate(crts/crt.pem) and its matching private key(crts/key.pem), owned by root with access permissions set to 0700.
You can create a self-signed certificate, or obtain one from a CA.
Currently, KMS persists data on mySQL. Future KMS releases may support different data stores. You need to create a mySQL database and make sure that proper authentication and authorization is required to access its tables. KMS will encrypt and persist keys and secrets to those tables.
You can create the 3 tables required like so:
```mySQL        
CREATE TABLE `keyring` ( `id` varbinary(128) NOT NULL, `k` varbinary(128) NOT NULL, PRIMARY KEY (`id`) );
CREATE TABLE `secrets` ( `id` varbinary(250) NOT NULL, `pair_k` varbinary(250) NOT NULL, `pair_v` longblob NOT NULL, PRIMARY KEY (`id`,`pair_k`) );
CREATE TABLE `tokens` ( `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `display_name` varbinary(128) DEFAULT NULL, `create_ts` int(10) unsigned NOT NULL, `domains` longblob NOT NULL, `iv` binary(16) NOT NULL, PRIMARY KEY (`id`) );
```             
The mySQL endpoint, which may include access credentials, needs to specified in a configuration file, or provided on startup when prompted.
To specify it using a configuration file, use the `-f <path>`. The configuration path must be owned by root, and permissions should be 0700, otherwise KMS will reject it.
The only configuration option currently supported is `persist.mysql.endpoint`. You can specify the endpoint like so: `persist.mysql.endpoint = endpoint`.
The mySQL endpoint format is  `user[:password@]hostname[:port]/databasename`. That is to say, password and port are optional, but I strongly suggest that you configure (user, password) based authentication for KMS mySQL tables. If port is not specified, port is assumed to be 3306.
                        
                                
## Master Key and Shares         
When KMS starts, it is in a `sealed state`. The only operation possible while in this state is `/unseal`. KMS cannot decrypt any information persisted unless unsealed first. Unsealing requires reconstruction of the `Master Key`, which in turn is used to decrypt a special KMS key, which is used to encrypt and decrypt keys and secrets. The master keys is not stored anywhere. It can only be derived from the master key shares. As opposed to creating a single master key and trusting a single operator with that key, KMS uses [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) to split the master created during initialisation into 1 or more shares, and trusted operators get exclusive ownership of those shares. Later, to unseal KMS, operators provide shares, in any order, and KMS, once it has enough shares, will reconstruct the master key, and transition to `unsealed` state.
                                
## Initialisation                
To initialise KMS, which can only be done once, you need to use `kms init <number of shares> <required shares to reconstruct the master key>`. A new master key is created, and then split into the number of shares you specified. KMS will initialise the database, and will then output the shares on screen, as well as a special `root authentication token`. You should then distribute the shares to trusted parties, and store the root token for later use (you should use 1Password or other such utilities to store the shares trusted to you, and the root token). Once KMS is initialised, you will not be able to reinitialise it.


## Example: initialising KMS
Create the required mySQL tables.
```bash
mysql -h <mysql_host> -u <mysql_username> --password=<mysql_password> -A <mysql_database>
mysql> CREATE TABLE `keyring` ( `id` varbinary(128) NOT NULL, `k` varbinary(128) NOT NULL, PRIMARY KEY (`id`) );
Query OK, 0 rows affected (0.00 sec)


mysql> CREATE TABLE `secrets` ( `id` varbinary(250) NOT NULL, `pair_k` varbinary(250) NOT NULL, `pair_v` longblob NOT NULL, PRIMARY KEY (`id`,`pair_k`) );
Query OK, 0 rows affected (0.00 sec)

mysql> CREATE TABLE `tokens` ( `id` int(10) unsigned NOT NULL AUTO_INCREMENT, `display_name` varbinary(128) DEFAULT NULL, `create_ts` int(10) unsigned NOT NULL, `domains` longblob NOT NULL, `iv` binary(16) NOT NULL, PRIMARY KEY (`id`) );
Query OK, 0 rows affected (0.00 sec)
```

Create a configuration file for KMS with just the mySQL endpoint.
```bash
echo "persist.mysql.endpoint = <mysql_username>:<mysql_password>@<mysql_host>/<mysql_database>" > kms.config
chmod 0700 kms.config
chown root kms.config
```

Initialise KMS. Split the master key into 5 shares, and require 3 shares to be able to reconstruct the master key.
```bash
./kms -f kms.config  init 5 3 
Root Token: iiBcRkH4OuardHV9l2JfmxLZiP24MtB513+0AJySKa35GdUymPzO7WT1G3Nkxmwt
Share 0: AQyfyiCT12bfu80igtyKe/cjk1J46121Vq1/8TtwS3mf/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Share 1: Atyq5+yhUFDyxCqUHvIXwe0JJ+VywG81xQW69Atge5YK/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Share 2: A67zRZePlFN40d6kFdm4TYzc5Lm6IeZksitTV4eZMaBw/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Share 3: BCJLADGe+MOWYbKwjqqGT7IwO5QQyUeK2tF3xB5AYARM/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Share 4: BVASokqwPMAcdEaAhYEpw9Pl+MjYKM7brf+eZ5K5KjI2/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Trusted operators should own those shares. A minimum of 3 shares are required to reconstruct the Master Key, and unseal KMS.
If you can't reconstruct the Master Key, you are toast. Backup often.
```
Distribute the shares to the trusted operators. For example, you can trust 2 shares with one operator, and 1 share with 3 operators, 1 for each. You can be as creative as you want with how you share those shares and who you trust those with. In this example, you will need 3 shares to reconstruct the master key, which means that, for instance, the operator who owns the 2 shares needs another operator (all remaining operators have 1 share) to unseal KMS, or 3 operators, each with 1 share, need to work together to unseal it.

Now assuming you have a certificate(`crts/crt.pem`) and its matching private key(`crts/key.pem`)
```bash
chown root crts/crt.pem crts/key.pem
chnod 0700 crts/crt.pem crts/key.pem
```

Now you can run KMS 
```bash
./kms -l :8282 -f kms.config 
KMS is ready and locked. You need to provide 3 shares to unlock it.
You cannot use it set or access secrets before you unlock it.
Accepting connections at https://0.0.0.0:8282
```

KMS is now running in unsealed state. To unseal it, using the root token provided during initialisation: 

```bash
curl "https://localhost:8282/unseal" -k -H "Authorization: KMS iiBcRkH4OuardHV9l2JfmxLZiP24MtB513+0AJySKa35GdUymPzO7WT1G3Nkxmwt" \
-d 'AQyfyiCT12bfu80igtyKe/cjk1J46121Vq1/8TtwS3mf/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
Atyq5+yhUFDyxCqUHvIXwe0JJ+VywG81xQW69Atge5YK/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU=
A67zRZePlFN40d6kFdm4TYzc5Lm6IeZksitTV4eZMaBw/prQqpvkLJ4DwOK6+U1ebIXjOjBgVza908tg5kiVWuIKloeeHoUdBfLXDpZDDR2BKKdiKOKl3y0W85aU2HRxNLSlozfojdllw/RTDI+tlIU='
```
Notice how we used the Authorization HTTP header with the root token, and how we used 3 of the seals. In actual use cases, a single operator shouldn’t have access to as many shares are required to reconstruct the master key. For this example, we assume that you do, for the sake of the tutorial.

If you have done this correctly, KMS will output `KMS unlocked` in standard output.




## Running KMS
Run `kms -l <listen address>`. The listen address can be :port, or address:port, to listen to a specific address. You can also use `-f <configuration file path>` to specify the mySQL endpoint in there, otherwise you will be prompted for the mySQL endpoint.

You should unseal the KMS instance for clients to be able to access it. KMS will accept HTTPS connections at the specified listen address.

## Requests Authentication and Authorization
All HTTP requests require authentication. To authenticate an HTTPS request, you need to use the `Authorization` HTTP header, using the `KMS` realm and the token, like so:
```
Authorization: KMS token
```
Almost all requests require authorization. When KMS is initialised, a special root token is created. That is the only token that can be used to access everything, and to create new tokens. To create a new token, you need to use the `/create_token` API.

## Keys and Secrets identifiers
A key or secret identifier is represented as a path with a "/" delimiter, and cannot be longer than 64 characters in length. 
Examples of key or secret identifiers:
- users/mail/100
- products/video_games/ps4/150


## API
Almost all requests require authentication using Authorization HTTP header, and almost all of them should be POST requests. Any exceptions will be noted here.

- `/create_token`  
This is how you can create new tokens. You need to provide a JSON dictionary in the POST request as the content, and you need to use the root authorization key to authorize the request.
The JSON dictionary structure should be as follows:
```json
{
  "name": "domain name",
  "domains": [
      {
          "domain": "domain path",
          "permissions": "representation of permissions"
      }
   ],
   "expires": unixTimestamp
}
```
where name is the name of token, for example, "application servers token", expires is the expiration date(number) expressed as a unix timestamp, and domains is an array of 1 or more domains. The domain is should have a trailing "/" An example of a domain is "users/", another example is "users/mail/".  Permissions is a string and can contain "r" or "w" characters. "r" enables read and "w" enables write, for the specified domain.
KMS will register the new token and will return the token identifier you can use from now on to authenticate HTTP requests.
 
When KMS needs to verify access for a specific key or secret, it will check against all defined domains for the token used in the HTTP authentication, and will determine permissions based on which domains match the key or secret. That means that, for example, you can set read and write permissions for "users/mail/", but only read permissions 
 for "users/"
 
- `/create_keys` 
Excepts 0 or more key identifiers, one per line, in the POST content, and for each such identifier, it will create a new key and associate it with it. The response will contain lines of `<identifier><space><base64 representation of key>` for each identifier specified.

- `/delete_keys` 
Expects 0 or more keys identifiers, one per line, in the POST content. For each such identifier, it will delete the key. It does not return any content in the response.

- `/set_keys` 
This is similar to create_keys, except that instead of expecting one key identifier per line, it expects `<key id><space><base64 representation of key>` per line. It will assign the key to the respective key identifier. It does not return any content in the response.

- `/encrypt` 
Expects `<key identifier><space><comma separated list of base 64 represented datums>` in a single line. It will encrypt each of those datums using the key identified by the key identifier, and it will return the base64 ciphertext for each of those datums, one per line, in the response.

- `/decrypt` 
-Expects `<key identifier><space><comma separated list of base 64 represented datums>` in a single line. It will decrypt each of those datums using the key identified by the key identifier, and it will return the base64 plaintext for each of those datums, one per line, in the response.

- `/seal` 
Will seal KMS. Only HTTP requests authenticated using the root token can seal KMS.

- `/status` 
This request can also executed using GET. It returns information about state(sealed, or not) and total shares provided so far.

- `/seal_status` 
This request can also be executed using GET. It returns 200 OK if KMS is unsealed, and 418 I am a Teapot if sealed. Useful for health checks.

- `/revoke_token` 
Expects a token in the request content payload. It will delete that token. It will not return any content in the response.

- `/unseal` 
It expects 0 or more master key seals, one per line. It will verify the seals, and if enough shares have been collected, it will try to unseal KMS. If it doesn't succeed, it will reset the number of seals collected.
If KMS is unsealed, the response will be "KMS is now UNLOCKED", otherwise, you will get a JSON dictionary with "cnt" as the total shares collected, and "required" as the number of shares required to reconstruct the master key.

- `/get_keys` 
Expects 0 or more key identifiers, one per line. KMS will return `<key identifier><space><base64 representation of the key>`  for each such identifier in the response.

- `/unwrap` 
Expects 0 or more `<key identifier><space><base64 representation of wrapped key>`, one per line. KMS will attempt to decrypt the wrapped key, and for each identifier, it will return`<key identifier><space><base64 representation of the unwrapped key>`. 

- `/get_secrets` 
Expects 0 or more lines of `<secret identifier><space><comma separated list of properties>`. It will return `<secret name><space><property name><=><base64 representation of property value>` for each of the defined properties.

- `/set_secrets` 
Expects 0 or more lines of `<secret identifier><comma separated list of assignments>`, where each assignment is `<property_name><=><base64 representation of value>`. If the value is empty, that property for that secret is deleted, otherwise the value of the secret's property is updated. The response contains no data.
