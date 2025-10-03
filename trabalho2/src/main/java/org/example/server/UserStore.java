package org.example.server;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class UserStore {
	public static final class StoredFile {
		public String name;
		public String b64;
		public long ts;
	}

	public static final class UserRec {
		public String username;
		public String pwdStored; // pbkdf2$sha256$iter$saltB64$dkB64
		public String saltB64;
		public String totpSecretBase32;
		public Map<String, StoredFile> files = new HashMap<>();
	}

	private final Map<String, UserRec> users = new HashMap<>();
	private final File dbFile;
	private final Gson gson = new Gson();

	public UserStore(File dbFile) {
		this.dbFile = dbFile;
		load();
	}

	public synchronized UserRec get(String u) {
		return users.get(u);
	}

	public synchronized boolean exists(String u) {
		return users.containsKey(u);
	}

	public synchronized void put(UserRec r) {
		users.put(r.username, r);
		persist();
	}

	public synchronized void putFile(String u, StoredFile sf) {
		users.get(u).files.put(sf.name, sf);
		persist();
	}

	public synchronized StoredFile getFile(String u, String name) {
		UserRec r = users.get(u);
		return r == null ? null : r.files.get(name);
	}

	private void load() {
		try {
			if (!dbFile.exists())
				return;
			try (Reader rd = new InputStreamReader(new FileInputStream(dbFile), StandardCharsets.UTF_8)) {
				Type t = new TypeToken<Map<String, UserRec>>() {
				}.getType();
				Map<String, UserRec> m = gson.fromJson(rd, t);
				if (m != null)
					users.putAll(m);
			}
		} catch (Exception ignored) {
		}
	}

	private void persist() {
		try (Writer wr = new OutputStreamWriter(new FileOutputStream(dbFile), StandardCharsets.UTF_8)) {
			gson.toJson(users, wr);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
