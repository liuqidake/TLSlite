import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Handshake {

	public static final BigInteger DH_GENERATOR = new BigInteger("2");
	private static final BigInteger DH_PRIME = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			+ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			+ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			+ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			+ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			+ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

	/**
	 * get certificate byte array from .pem file
	 * 
	 * @param certificateName
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKey(String keyName) {

		try {
			Path path = Paths.get(keyName);
			byte[] privKeyByteArray;
			privKeyByteArray = Files.readAllBytes(path);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
			return myPrivKey;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

	}

	public static Certificate getCertificate(String certName) {
		FileInputStream in;
		try {
			in = new FileInputStream(certName);
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate cer = factory.generateCertificate(in);
			return cer;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;

	}

	/**
	 * get Diffie Hellman public key
	 * 
	 * @return
	 */
	public static BigInteger getDHPublicKey(int randomPrivateKey) {

		return (DH_GENERATOR.pow(randomPrivateKey)).mod(DH_PRIME);
	}

	/**
	 * get shared secret key
	 */
	public static BigInteger getSharedSecretKey(int randomPrivateKey, BigInteger newGenerator) {
		return newGenerator.pow(randomPrivateKey).mod(DH_PRIME);
	}

	/**
	 * Use the private key to sign DH public key
	 */
	public static byte[] signDHPublicKey(PrivateKey privKey, BigInteger DHkey) {
		try {
			Signature sig = Signature.getInstance("SHA256WithRSA");
			sig.initSign(privKey);
			// System.out.println(DHkey.toString());
			sig.update(DHkey.toByteArray());
			byte[] bytes = sig.sign();
			// System.out.println(bytes.length);
			return bytes;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Send certificate, DHkey and signed DHkey for verification
	 * 
	 * @param out
	 * @param cert
	 * @param DHkey
	 * @param signedDHkey
	 */
	public static void sendVerificationInfo(ObjectOutputStream out, Certificate cert, BigInteger DHkey,
			byte[] signedDHkey) {
		try {
			out.writeObject(cert);
			out.writeObject(DHkey);
			out.writeObject(signedDHkey);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Verify the certificate
	 * 
	 * @param in
	 * @param cert
	 * @return
	 */
	public static boolean verifyCertificate(Certificate verified) {
		try {
			Certificate cert = getCertificate("CAcertificate.pem");
			verified.verify(cert.getPublicKey());
			return true;
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	public static boolean authenticate(Certificate sentCert, BigInteger DHKey, byte[] signedDHkey) {
		try {
			Signature sig = Signature.getInstance("SHA256WithRSA");

			sig.initVerify(sentCert.getPublicKey());
			sig.update(DHKey.toByteArray());
			// verify the certificate and the DH public key
			return verifyCertificate(sentCert) && sig.verify(signedDHkey);

		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

}
