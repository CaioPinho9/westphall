package org.example.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public final class Http {
	private final HttpClient hc = HttpClient.newHttpClient();
	private final String base;
	private String token; // X-Session-Token

	public Http(String base) {
		this.base = base;
	}

	public void setToken(String t) {
		this.token = t;
	}

	public String post(String path, String json) throws IOException, InterruptedException {
		HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(json));
		if (token != null)
			b.header("X-Session-Token", token);
		HttpResponse<String> r = hc.send(b.build(), HttpResponse.BodyHandlers.ofString());
		if (r.statusCode() >= 200 && r.statusCode() < 300)
			return r.body();
		throw new IOException("HTTP " + r.statusCode() + ": " + r.body());
	}

	public String get(String path) throws IOException, InterruptedException {
		HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path)).GET();
		if (token != null)
			b.header("X-Session-Token", token);
		HttpResponse<String> r = hc.send(b.build(), HttpResponse.BodyHandlers.ofString());
		if (r.statusCode() >= 200 && r.statusCode() < 300)
			return r.body();
		throw new IOException("HTTP " + r.statusCode() + ": " + r.body());
	}
}
