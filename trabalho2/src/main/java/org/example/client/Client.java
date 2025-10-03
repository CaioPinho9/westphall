package org.example.client;

import com.google.gson.Gson;
import org.example.common.ApiModels.*;
import org.example.common.CryptoUtils;

import org.apache.commons.codec.binary.Base32;

import java.io.*;
import java.net.URLEncoder;
import java.nio.file.*;
import java.util.*;

public final class Client {
	private static final Scanner in = new Scanner(System.in);
	private static final Gson gson = new Gson();

	public static void main(String[] args) throws Exception {
		String base = System.getProperty("server", "http://localhost:8080");
		Http http = new Http(base);
		System.out.println("Cliente conectado a: " + base);

		while (true) {
			System.out.println("\n[1] Cadastrar [2] Login+TOTP [3] Upload cifrado [4] Download+decifra [0] Sair");
			System.out.print("> ");
			String op = in.nextLine().trim();
			try {
				switch (op) {
				case "1" -> cadastrar(http);
				case "2" -> loginTotp(http);
				case "3" -> upload(http);
				case "4" -> download(http);
				case "0" -> {
					return;
				}
				default -> System.out.println("Opcao invalida");
				}
			} catch (Exception e) {
				System.out.println("Erro: " + e.getMessage());
			}
		}
	}

	private static void cadastrar(Http http) throws Exception {
		System.out.print("Usuario: ");
		String u = in.nextLine();
		System.out.print("Senha: ");
		String p = (System.console() != null) ? new String(System.console().readPassword()) : in.nextLine();
		String body = gson.toJson(new RegisterReq(u, p));
		String resp = http.post("/register", body);
		RegisterResp r = gson.fromJson(resp, RegisterResp.class);
		System.out.println("Cadastrado. Escaneie o QR no app TOTP.");

		// Salva PNG em arquivo
		String dataUri = r.qrcodeDataUri();
		String b64 = dataUri.substring(dataUri.indexOf(",") + 1);
		byte[] png = Base64.getDecoder().decode(b64);
		Path out = Paths.get("qrcode-" + u + ".png");
		Files.write(out, png);
		System.out.println("QR salvo em: " + out.toAbsolutePath());

		// Mostra segredo Base32 também (uso de commons-codec)
		byte[] raw = new Base32().decode(r.secretBase32());
		System.out.println("Secret(Base32)=" + r.secretBase32());
		System.out.println("Secret(hex)=" + CryptoUtils.toHex(raw));
	}

	private static void loginTotp(Http http) throws Exception {
		System.out.print("Usuario: ");
		String u = in.nextLine();
		System.out.print("Senha: ");
		String p = (System.console() != null) ? new String(System.console().readPassword()) : in.nextLine();
		String r1 = http.post("/login", gson.toJson(new LoginReq(u, p)));
		LoginResp L = gson.fromJson(r1, LoginResp.class);
		if (!L.ok()) {
			System.out.println(L.message());
			return;
		}
		System.out.print("Codigo TOTP: ");
		String code = in.nextLine().trim();
		String r2 = http.post("/verify-totp", gson.toJson(new TotpReq(u, code)));
		TotpResp T = gson.fromJson(r2, TotpResp.class);
		if (!T.ok()) {
			System.out.println(T.message());
			return;
		}
		http.setToken(T.sessionToken());
		// Guarda sal e params em memória desta execução
		Session.kdf = L.kdf();
		Session.N = L.N();
		Session.r = L.r();
		Session.p = L.p();
		Session.dkLen = L.dkLen();
		Session.salt = Base64.getDecoder().decode(L.saltB64());
		Session.user = u;
		System.out.println("Autenticado. Sessao=" + T.sessionToken());
	}

	private static void upload(Http http) throws Exception {
		mustAuth();
		System.out.print("Arquivo plaintext: ");
		Path inFile = Paths.get(in.nextLine());
		System.out.print("Senha (para derivar chave): ");
		String p = (System.console() != null) ? new String(System.console().readPassword()) : in.nextLine();
		byte[] plain = Files.readAllBytes(inFile);

		byte[] key = deriveKey(p);
		byte[] blob = org.example.common.CryptoUtils.encryptAesGcm(key, plain, Session.user.getBytes());
		String b64 = Base64.getEncoder().encodeToString(blob);
		http.post("/upload", gson.toJson(new UploadReq(inFile.getFileName().toString(), b64)));
		System.out.println("Enviado (cifrado). Tamanho= " + blob.length + " bytes");
	}

	private static void download(Http http) throws Exception {
		mustAuth();
		System.out.print("Nome do arquivo no servidor: ");
		String name = in.nextLine();
		String resp = http.get("/download?filename=" + URLEncoder.encode(name, java.nio.charset.StandardCharsets.UTF_8));
		DownloadResp r = gson.fromJson(resp, DownloadResp.class);
		System.out.print("Senha (para derivar chave): ");
		String p = (System.console() != null) ? new String(System.console().readPassword()) : in.nextLine();

		byte[] key = deriveKey(p);
		byte[] blob = Base64.getDecoder().decode(r.dataB64());
		byte[] plain = org.example.common.CryptoUtils.decryptAesGcm(key, blob, Session.user.getBytes());
		Path out = Paths.get("decifrado-" + name);
		Files.write(out, plain);
		System.out.println("Decifrado em: " + out.toAbsolutePath());
	}

	private static byte[] deriveKey(String password) {
		if ("scrypt".equalsIgnoreCase(Session.kdf))
			return CryptoUtils.scrypt(password, Session.salt, Session.N, Session.r, Session.p, Session.dkLen);
		else
			return CryptoUtils.pbkdf2(password, Session.salt, 200_000, Session.dkLen);
	}

	private static void mustAuth() {
		if (Session.user == null)
			throw new IllegalStateException("faça login + TOTP primeiro");
	}

	// guarda params KDF da sessão corrente (na memória)
	static final class Session {
		static String user, kdf;
		static int N, r, p, dkLen;
		static byte[] salt;
	}
}
