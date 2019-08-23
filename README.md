# TLSlite
## Creating + Signing Certificates

We'll use three RSA public/private key pairs in our system:

"Certificate Authority" -- we'll use this keypair to sign and verify certificates for the client and server. This our standin for a service like Versign or LetsEncrypt
Server -- will have a certificate signed by the CA and corresponding private key. It will use these to authenticate itself to the client/perform a handshake
Client -- same deal as the server
We'll use OpenSSL to generate our public/private key pairs and certificates. Macos comes with openssl installed and these instructions are tested with that version. If you use the homebrew version, things might be different...

## Generate a RSA public/private key pair for the "Certificate Authority"

openssl req -x509 -newkey rsa:4096 -keyout CAprivateKey.pem -out CAcertificate.pem -days 30 -nodes

Let's walk through this:

req -- make a new certificate
-x509 -- in x509 format (the standard format)
-newkey -- generate a new RSA keypair for this certificate
rsa:4096 -- make it a 4096 bit RSA key
-keyout -- filename for the private key
-out -- filename for the certificate
-days 30 -- this certificate expires 30 days from now
-nodes -- don't encrypt the certificate/private key
This command will take a while to run because it has to find big prime numbers and do the other number theory stuff to pick the RSA exponents.

## Generate client/server keys + "certificate signature requests"

Next we'll pick the keys for the client and server and a request for the CA to sign.

openssl req -new -newkey rsa:4096 -nodes -keyout serverPrivate.key -out server.csr

This will produce the private key and the request for the CA to sign.

Setup CA for signing, sign CSRs

Download this CA config file. It specifies a bunch of information for the CA, almost all of which is overkill for us, but seems to be necessary <shrug emoji>.

It specifies a bunch of files + directories that need to exist to sign the CSRs to produce client + server certificates.

mkdir certs newcerts
touch index.txt
echo 1000 > serial
index.txt is the "database" which lists all the certificates that have been issued by our CA (again, overkill for us, but it makes OpenSSL happy)

Serial keeps track of the serial numbers assigned to those certificates (it needs to be unique per certificate issued)

At this point, we can fulfill the CSR requests:

openssl ca -config config.cnf -cert CAcertificate.pem -keyfile CAprivateKey.pem -in server.csr -out CASignedServerCertificate.pem

You'll probably need to change/fix up the filenames, but this command will take the CA certificate, CA private key, and CSR and will produce a certificate signed by our CA. Note that pretty much the only field that you'll be prompted to enter that really matters is the "common name." The index.txt file ensures that the CA does NOT sign multiple certificates for the same common name, so make sure you pick different names for the client + server (like "client" and "server")

Double checking

Our certificate SHOULD be contain the server's public key. To verify that it matches our private key, we can confirm that the modulus (the big N) is the same for our certificate and the private key. We can use openssl to do this. Because N is huge, we run it through a hash function and compare the hashes.

openssl rsa -in clientPrivate.key -noout -modulus | openssl sha256 for the private key and openssl x509 -noout -modulus -in CASignedClientCertificate.pem | openssl sha256 for the certificate should produce the same hash.

formats

OpenSSL produces "PEM" format private key files which are a pain to work with Java (it's a text based format). The DER format is easier to work with (it's a binary format). We can use OpenSSL to convert our PEM private keys to DER private keys:

openssl pkcs8 -topk8 -outform DER -in serverPrivate.key -out serverPrivateKey.der -nocrypt

## Handshake

Now that we have all the necessary keys generated, we can start to implement our communications protocol.

The client and server will each authenticate each other using a simplified TLS handshake as follows:

Client: Nonce1 (32 bytes from a SecureRandom object)
Server: Server Certificate, DiffieHellman public key, Signed DiffieHellman public key (Sign[g^ks % N, Spub])
Client: Client Certificate, DiffieHellman public key, Signed DiffieHellman public key (Sign[g^kc % N, Cpub])
//Client and server compute the shared secret here using DH
//client and server derive 6 session keys from the shared secret. 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF (below)
Server: MAC(all handshake messages so far, Server's MAC key)
Client: MAC(all handshake messages so far including the previous step, Client's MAC key).
At this point, the client and server have authenticated. We'll create a "Certificate Authority" which will (before we run the program) sign certificates for the client and server. For a real application, the certificate verification would makes sure that the chain of trust goes up to a trusted certificate authority. For this application, when we receive a certificate, we'll make sure that it is signed by our CA.

Key generation: HKDF

Diffie Hellman gives us a shared secret key, but it might be too small or be otherwise unsuitable to use as keys for AES or MACs. We'll run it through a "key derivation function" to turn it into a bunch of nice random looking keys. We'll use the HKDF (parts not relevant for our use omitted)


def hdkfExpand(input, tag): //tag is a string, but probably convenient to take its contents as byte[]
	okm = HMAC(key = input,  data = tag concatenated with a byte with value 1)
	return first 16 bytes of okm


def makeSecretKeys(clientNonce, sharedSecretFromDiffieHellman):
	prk = HMAC(key = clientNonce, data = sharedSecretFromDiffieHellman)
	serverEncrypt = hkdfExpand(prk, "server encrypt")
	clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt")
	serverMAC = hkdfExpand(clientEncrypt, "server MAC")
	clientMAC = hkdfExpand(serverMAC, "client MAC")
	serverIV = hkdfExpand(clientMAC, "server IV")
	clientIV = hkdfExpand(serverIV, "client IV")

So, each key is essentially the result of hashing one of the other keys and adding in an extra "tag" to make sure they can't accidentally be mistaken for one another. Use the HmacSHA256 HMAC function.

Note, that Java has special types for the various types of secret keys. You'll probably want to use the SecretKeySpec class which takes bytes and turns it into a key for a given algorithm (it doesn't change the value of the key, just marks its type). For IVs, use the IvParameterSpec class.

## Message format

After the handshake, each message will use a format similar to the TLS record format, but we'll let Java take care of the specifics by making use of the ObjectOutputStream and ObjectInputStream classes.

To send a message:

Compute the HMAC of the message using the appropriate MAC key
Use the cypher to encrypt the message data concatenated with the MAC
Send/receive the resulting byte array using the Object*Stream classes (it will include the array size, etc automatically).
For encryption, we'll use AES 128 in CBC mode. For MAC, we'll use HMAC using SHA256 as our hash function.

