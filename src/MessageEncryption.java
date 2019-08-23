import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageEncryption {

	public static void sendMessage(byte[] message, ObjectOutputStream out, Mac macKey, SecretKeySpec sKey,
			IvParameterSpec IV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		// make a cipher object
		Cipher ci;
		ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.ENCRYPT_MODE, sKey, IV);

		byte[] msgHash =macKey.doFinal(message);
		byte[] all = new byte[message.length + msgHash.length];
		System.arraycopy(message, 0, all, 0, message.length);
		System.arraycopy(msgHash, 0, all, message.length, msgHash.length);
		out.writeObject(ci.doFinal(all));

	}

	public static String readMessages(ObjectInputStream in, SecretKeySpec sKey, IvParameterSpec IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, ClassNotFoundException, IOException, IllegalBlockSizeException,
			BadPaddingException {

		// make a cipher object
		Cipher ci;
		ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.DECRYPT_MODE, sKey, IV);

		// get the cipher texts
		byte[] cipher = (byte[]) in.readObject();
		// decode the cipher texts, get the bytes array with message concatenated with
		// hash value of this message
		byte[] hashedCipher = ci.doFinal(cipher);
		
		byte[] message = new byte[hashedCipher.length-32];
		System.arraycopy(hashedCipher, 0, message, 0, message.length);

		return new String(message);

	}

	/**
	 * Server sends a large file to client
	 * 
	 * @param message
	 * @param out
	 * @param macKey
	 * @param sKey
	 * @param IV
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static void sendFile(String fileName, ObjectOutputStream out, Mac macKey, SecretKeySpec sKey,
			IvParameterSpec IV) {
		try (FileInputStream file = new FileInputStream(fileName)) {
			byte[] message = new byte[1024];
			while (true) {
				int len = file.read(message);
				if (len == -1)
					break;
				if (len < 1024) {
					sendMessage(message, out, macKey, sKey, IV);
					break;
				} else {
					sendMessage(message, out, macKey, sKey, IV);
					message = new byte[1024];
				}
			}
			return;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
