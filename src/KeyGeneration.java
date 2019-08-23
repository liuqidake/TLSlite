
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KeyGeneration {
	
	public static byte[] Hmac(byte[] key, byte[] data) {
		try {
			Mac Hmac = Mac.getInstance("HmacSHA256");
			SecretKeySpec secretKey = new SecretKeySpec(key,"HmacSHA256");
			Hmac.init(secretKey);
			byte[] tagWithOneMoreByte = new byte[data.length+1];
			System.arraycopy(data, 0, tagWithOneMoreByte, 0, data.length);
			tagWithOneMoreByte[tagWithOneMoreByte.length-1] = (byte)1;
			return  Hmac.doFinal(tagWithOneMoreByte);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;	
	}
	
	public static byte[] hkdfExpand(byte[] input, byte[] data) {
		byte[] okm = Hmac(input, data);
		byte[] first16Bytes = new byte[16];
		System.arraycopy(okm, 0, first16Bytes, 0, 16);
		
		return first16Bytes;
	}
	
	
	public static List<byte[]> makeSecretKeys(byte[] clientNonce, BigInteger secretKey) {
		
		byte[] prk = Hmac(clientNonce, secretKey.toByteArray());
		List<byte[]> keys = new ArrayList<>();
		
		byte[] serverEncrypt = hkdfExpand(prk,"server encrypt".getBytes());
		keys.add(serverEncrypt);
		
		byte[] clientEncrypt = hkdfExpand(serverEncrypt,"client encrypt".getBytes());
		keys.add(clientEncrypt);
		
		byte[] serverMAC = hkdfExpand(clientEncrypt,"server MAC".getBytes());
		keys.add(serverMAC);
		
		byte[] clientMAC = hkdfExpand(serverMAC,"client MAC".getBytes());
		keys.add(clientMAC);
		
		byte[] serverIV = hkdfExpand(clientMAC,"server IV".getBytes());
		keys.add(serverIV);
		
		byte[] clientIV = hkdfExpand(serverIV,"client IV".getBytes());
		keys.add(clientIV);
		
		return keys;
		
	}
}
