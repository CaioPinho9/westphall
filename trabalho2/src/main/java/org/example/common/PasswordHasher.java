package org.example.common;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class PasswordHasher {
	public static final int DEFAULT_ITER = 200_000;
	public static final int SALT_LEN = 16;
	public static final int HASH_LEN = 32; // 256 bits

	public static byte[] randomSalt() {
		byte[] s = new byte[SALT_LEN];
		new SecureRandom().nextBytes(s);
		return s;
	}

	public static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int lenBytes) {
		try {
			PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, lenBytes * 8);
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			return skf.generateSecret(spec).getEncoded();
		} catch (Exception e) {
			throw new RuntimeException("PBKDF2 error", e);
		}
	}

	public static String hashForStorage(String password, byte[] salt) {
		byte[] dk = pbkdf2(password.toCharArray(), salt, DEFAULT_ITER, HASH_LEN);
		return "pbkdf2$sha256$" + DEFAULT_ITER + "$" + Base64.getEncoder().encodeToString(salt) +
				"$" + Base64.getEncoder().encodeToString(dk);
	}

	public static boolean verify(String stored, String password) {
		try {
			String[] parts = stored.split("\\$");
			int it = Integer.parseInt(parts[2]);
			byte[] salt = Base64.getDecoder().decode(parts[3]);
			byte[] expected = Base64.getDecoder().decode(parts[4]);
			byte[] got = pbkdf2(password.toCharArray(), salt, it, expected.length);
			if (got.length != expected.length)
				return false;
			int diff = 0;
			for (int i = 0; i < got.length; i++)
				diff |= (got[i] ^ expected[i]);
			return diff == 0;
		} catch (Exception e) {
			return false;
		}
	}
}
