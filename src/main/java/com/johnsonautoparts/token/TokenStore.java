package com.johnsonautoparts.token;

import java.time.*;
import java.util.*;
import java.util.concurrent.*;

import javax.servlet.http.HttpServletRequest;

import com.johnsonautoparts.exception.AppException;

public interface TokenStore {

	String create(Token token) throws AppException;

	class Token {
		public final Instant expiry;
		public final String username;
		public final Map<String, String> attributes;

		public Token(Instant expiry, String username) {
			this.expiry = expiry;
			this.username = username;
			this.attributes = new ConcurrentHashMap<>();
		}
	}
}
