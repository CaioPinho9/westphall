package org.example.common;


public final class ApiModels {
	// Requests
	public record RegisterReq(String username, String password) {
	}

	public record LoginReq(String username, String password) {
	}

	public record TotpReq(String username, String code) {
	}

	public record UploadReq(String filename, String dataB64) {
	}

	// Responses
	public record RegisterResp(String message, String issuer, String account, String secretBase32,
							   String otpauthUri, String qrcodeDataUri) {
	}

	public record LoginResp(boolean ok, String message, String kdf, int N, int r, int p,
							int dkLen, String saltB64, int totpPeriod, int totpDigits) {
	}

	public record TotpResp(boolean ok, String sessionToken, String message) {
	}

	public record DownloadResp(String filename, String dataB64) {
	}
}
