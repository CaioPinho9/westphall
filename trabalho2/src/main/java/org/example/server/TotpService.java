package org.example.server;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.time.*;
import dev.samstevens.totp.qr.*;
import dev.samstevens.totp.secret.*;

/**
 * Serviço TOTP: gera segredo, QR e valida códigos.
 */
public final class TotpService {
	private final String issuer;

	public TotpService(String issuer) {
		this.issuer = issuer;
	}

	public String newSecret() {
		SecretGenerator gen = new DefaultSecretGenerator();
		return gen.generate(); // Base32
	}

	public byte[] qrPng(String account, String secretBase32) {
		try {
			QrData data = new QrData.Builder()
					.label(account)
					.secret(secretBase32)
					.issuer(issuer)
					.algorithm(HashingAlgorithm.SHA1)
					.digits(6)
					.period(30)
					.build();
			QrGenerator g = new ZxingPngQrGenerator();
			return g.generate(data); // image/png
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public boolean verify(String secretBase32, String code) {
		TimeProvider time = new SystemTimeProvider();
		DefaultCodeVerifier v = new DefaultCodeVerifier(new DefaultCodeGenerator(), time);
		v.setAllowedTimePeriodDiscrepancy(1); // ±30s
		return v.isValidCode(secretBase32, code);
	}
}
