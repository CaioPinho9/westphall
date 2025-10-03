package org.example.common;

import org.bouncycastle.crypto.generators.SCrypt;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public final class CryptoUtils {
	private static final SecureRandom RNG = new SecureRandom();
	public static final int GCM_TAG_BITS = 128;
	public static final int GCM_IV_LEN = 12; // recomendado para GCM

	public static byte[] scrypt(String password, byte[] salt, int N, int r, int p, int dkLen) {
		return SCrypt.generate(password.getBytes(StandardCharsets.UTF_8), salt, N, r, p, dkLen);
	}

	public static byte[] pbkdf2(String password, byte[] salt, int iter, int dkLen) {
		return PasswordHasher.pbkdf2(password.toCharArray(), salt, iter, dkLen);
	}

	public static byte[] rand(int len) {
		byte[] b = new byte[len];
		RNG.nextBytes(b);
		return b;
	}

	public static byte[] encryptAesGcm(byte[] key, byte[] plaintext, byte[] aad) {
		try {
			byte[] iv = rand(GCM_IV_LEN);
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
			if (aad != null)
				c.updateAAD(aad);
			byte[] ct = c.doFinal(plaintext);
			ByteBuffer bb = ByteBuffer.allocate(1 + iv.length + ct.length);
			bb.put((byte) 1); // versão do formato
			bb.put(iv);
			bb.put(ct);
			return bb.array();
		} catch (Exception e) {
			throw new RuntimeException("AES-GCM encrypt error", e);
		}
	}

	public static byte[] decryptAesGcm(byte[] key, byte[] blob, byte[] aad) {
		try {
			ByteBuffer bb = ByteBuffer.wrap(blob);
			byte ver = bb.get();
			if (ver != 1)
				throw new IllegalArgumentException("Versão de blob inválida");
			byte[] iv = new byte[GCM_IV_LEN];
			bb.get(iv);
			byte[] ct = new byte[bb.remaining()];
			bb.get(ct);
			Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
			if (aad != null)
				c.updateAAD(aad);
			return c.doFinal(ct);
		} catch (Exception e) {
			throw new RuntimeException("AES-GCM decrypt error", e);
		}
	}

	// Auxiliares demonstrando uso de commons-codec (Base32 e Hex)
	public static String toBase32(byte[] data) {
		return new Base32().encodeToString(data);
	}

	public static byte[] fromBase32(String s) {
		return new Base32().decode(s);
	}

	public static String toHex(byte[] data) {
		return Hex.encodeHexString(data);
	}
}
