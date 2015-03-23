package cat.copernic;


import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String toHexadecimal(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();

		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	public static enum KeySize {
		SIZE_128(128), SIZE_192(192), SIZE_256(256);

		private int size;
		KeySize(int size){
			this.size = size;
		}
	}

	public static SecretKey passwordKeyGeneration(String password, KeySize keySize) {
		SecretKey sKey = null;

		try {
			byte[] data = password.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(data);
			byte[] key = Arrays.copyOf(hash, keySize.size/8);
			sKey = new SecretKeySpec(key, "AES");
		} catch (Exception ex) {
			System.err.println("Error generant la clau:" + ex);
		}

		return sKey;
	}

	public static byte[] encryptData(javax.crypto.SecretKey sKey, byte[] data) {
		byte[] encryptedData = null;
		try {
			javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, sKey);
			encryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return encryptedData;
	}
	
	public static byte[] decryptData(SecretKey sKey, byte[] data) {
		byte[] encryptedData = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sKey);
			encryptedData = cipher.doFinal(data);
		} catch (Exception ex) {
			System.err.println("Error xifrant les dades: " + ex);
		}
		return encryptedData;
	}

	public static void main(String[] args) throws Exception {

		if (args.length < 3) {
			System.out.println("symmetric <encrypt|decrypt> <message> <key>");
			return;
		}

		String msg=args[2];
		String pass=args[3];
		byte[] arrayb;
		byte[] arrayb2;

		switch (args[1]) {
		case "encrypt":
			SecretKey skey = passwordKeyGeneration(pass,KeySize.SIZE_128);
			arrayb=msg.getBytes();
			System.out.println(toHexadecimal(encryptData(skey, arrayb)));
			break;
		case "decrypt":
			SecretKey skey2 = passwordKeyGeneration(pass,KeySize.SIZE_128);
			arrayb=hexStringToByteArray(msg);
			arrayb2=decryptData(skey2, arrayb);
			String msg2=new String(arrayb2);
			System.out.println(msg2);
			
			break;
		default:
			System.out.println("Solo ---> encrypt o decrypt");
		}
	}


}
