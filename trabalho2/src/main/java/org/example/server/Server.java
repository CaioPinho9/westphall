package org.example.server;

import org.example.common.PasswordHasher;
import org.example.common.ApiModels.*;

import com.google.gson.Gson;

import com.sun.net.httpserver.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Server {
	private static final Gson gson = new Gson();
	private static final UserStore store = new UserStore(new File("server-db.json"));
	private static final TotpService totp = new TotpService("INE5680-App");
	private static final Map<String, String> sessions = new HashMap<>(); // token -> username

	public static void main(String[] args) throws Exception {
		int port = 8080;
		HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
		s.createContext("/register", j(Server::doRegister));
		s.createContext("/login", j(Server::doLogin));
		s.createContext("/verify-totp", j(Server::doVerify));
		s.createContext("/upload", j(Server::doUpload));
		s.createContext("/download", j(Server::doDownload));
		s.createContext("/qrcode", Server::doQr);
		s.setExecutor(null);
		System.out.println("Servidor na porta " + port);
		s.start();
	}

	private static void doRegister(HttpExchange ex) throws IOException {
		RegisterReq req = read(ex, RegisterReq.class);
		if (store.exists(req.username())) {
			send(ex, 409, "{\"error\":\"usuario existe\"}");
			return;
		}
		byte[] salt = PasswordHasher.randomSalt();
		String stored = PasswordHasher.hashForStorage(req.password(), salt);

		// Gera segredo TOTP (Base32)
		String secret = totp.newSecret();
		byte[] png = totp.qrPng(req.username(), secret);
		String dataUri = "data:image/png;base64," + Base64.getEncoder().encodeToString(png);

		UserStore.UserRec u = new UserStore.UserRec();
		u.username = req.username();
		u.pwdStored = stored;
		u.saltB64 = Base64.getEncoder().encodeToString(salt);
		u.totpSecretBase32 = secret;
		store.put(u);

		String otpauthUri = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30",
				"INE5680-App", req.username(), secret, "INE5680-App");

		RegisterResp resp = new RegisterResp("ok", "INE5680-App", req.username(), secret, otpauthUri, dataUri);
		send(ex, 200, gson.toJson(resp));
	}

	private static void doLogin(HttpExchange ex) throws IOException {
		LoginReq req = read(ex, LoginReq.class);
		UserStore.UserRec u = store.get(req.username());
		if (u == null || !PasswordHasher.verify(u.pwdStored, req.password())) {
			send(ex, 401, "{\"ok\":false,\"message\":\"login invalido\"}");
			return;
		}
		// retorna parâmetros do KDF e salt (para cifrar no cliente)
		send(ex, 200, gson.toJson(new LoginResp(true, "ok",
				"scrypt", 1 << 14, 8, 1, 32, u.saltB64, 30, 6)));
	}

	private static void doVerify(HttpExchange ex) throws IOException {
		TotpReq req = read(ex, TotpReq.class);
		UserStore.UserRec u = store.get(req.username());
		boolean ok = (u != null) && totp.verify(u.totpSecretBase32, req.code());
		if (!ok) {
			send(ex, 401, gson.toJson(new TotpResp(false, null, "totp invalido")));
			return;
		}
		String token = UUID.randomUUID().toString();
		sessions.put(token, req.username());
		send(ex, 200, gson.toJson(new TotpResp(true, token, "ok")));
	}

	private static void doUpload(HttpExchange ex) throws IOException {
		String user = auth(ex);
		if (user == null) {
			send(ex, 401, "{\"error\":\"sem sessao\"}");
			return;
		}
		UploadReq req = read(ex, UploadReq.class);
		UserStore.StoredFile sf = new UserStore.StoredFile();
		sf.name = req.filename();
		sf.b64 = req.dataB64();
		sf.ts = System.currentTimeMillis();
		store.putFile(user, sf);
		send(ex, 200, "{\"ok\":true}");
	}

	private static void doDownload(HttpExchange ex) throws IOException {
		String user = auth(ex);
		if (user == null) {
			send(ex, 401, "{\"error\":\"sem sessao\"}");
			return;
		}
		Map<String, String> q = splitQuery(ex.getRequestURI());
		String name = q.get("filename");
		UserStore.StoredFile sf = store.getFile(user, name);
		if (sf == null) {
			send(ex, 404, "{\"error\":\"nao encontrado\"}");
			return;
		}
		send(ex, 200, gson.toJson(new DownloadResp(sf.name, sf.b64)));
	}

	private static void doQr(HttpExchange ex) throws IOException {
		Map<String, String> q = splitQuery(ex.getRequestURI());
		String user = q.get("user");
		UserStore.UserRec u = store.get(user);
		if (u == null) {
			ex.sendResponseHeaders(404, -1);
			return;
		}
		byte[] png = totp.qrPng(user, u.totpSecretBase32);
		ex.getResponseHeaders().add("Content-Type", "image/png");
		ex.sendResponseHeaders(200, png.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(png);
		}
	}

	// util
	private static String auth(HttpExchange ex) {
		String token = ex.getRequestHeaders().getFirst("X-Session-Token");
		return sessions.get(token);
	}

	private static <T> T read(HttpExchange ex, Class<T> cls) throws IOException {
		try (Reader r = new InputStreamReader(ex.getRequestBody(), StandardCharsets.UTF_8)) {
			return new Gson().fromJson(r, cls);
		}
	}

	private static void send(HttpExchange ex, int code, String body) throws IOException {
		ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
		byte[] b = body.getBytes(StandardCharsets.UTF_8);
		ex.sendResponseHeaders(code, b.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(b);
		}
	}

	private static HttpHandler j(ThrowingHandler h) {
		return ex -> {
			try {
				h.handle(ex);
			} catch (Exception e) {
				e.printStackTrace();
				String msg = "{\"error\":\"" + e.getClass().getSimpleName() + ": " + e.getMessage() + "\"}";
				send(ex, 500, msg);
			}
		};
	}

	@FunctionalInterface private interface ThrowingHandler {
		void handle(HttpExchange ex) throws Exception;
	}

	private static Map<String, String> splitQuery(URI u) {
		Map<String, String> m = new HashMap<>();
		String q = u.getRawQuery();
		if (q == null)
			return m;
		for (String p : q.split("&")) {
			int i = p.indexOf('=');
			String k = URLDecoder.decode(i > 0 ? p.substring(0, i) : p, StandardCharsets.UTF_8);
			String v = i > 0 ? URLDecoder.decode(p.substring(i + 1), StandardCharsets.UTF_8) : "";
			m.put(k, v);
		}
		return m;
	}
}
