package com.johnsonautoparts.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.time.Instant;
import java.util.*;

import com.johnsonautoparts.exception.AppException;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.*;

public class SignedJwtTokenStore implements TokenStore {
  private final JWSSigner signer;
  private final JWSVerifier verifier;
  private final JWSAlgorithm algorithm;
  private final String audience;

  public SignedJwtTokenStore(HttpServletRequest request, String audience) throws AppException {
    HttpSession session = request.getSession();

    // check is session is null
    if (session == null) {
      throw new AppException("SignedJwtTokenStore has null session");
    }

    // check for secret in session
    Object secretObj = session.getAttribute("secret");
    if (secretObj instanceof byte[]) {
      throw new AppException("SignedJwtTokenStore cannot find secret in session");
    }

    try {
      // set the signer
      byte[] secret = (byte[]) secretObj;
      this.signer = new MACSigner(secret);

      // set the verifier
      verifier = new MACVerifier(secret);

      // set the algorithm to HMAC SHA256
      this.algorithm = JWSAlgorithm.HS256;

      // set the audience
      this.audience = audience;
    } catch (KeyLengthException kle) {
      throw new AppException(
          "SignedJwtTokenStore received key with wrong length: " + kle.getMessage());
    } catch (JOSEException je) {
      throw new AppException("SignedJwtTokenStore caught JOSEException: " + je.getMessage());
    }
  }

  @Override
  public String create(Token token) throws AppException {
    JWTClaimsSet claimsSet =
        new JWTClaimsSet.Builder()
            .subject(token.username)
            .audience(audience)
            .expirationTime(Date.from(token.expiry))
            .claim("attrs", token.attributes)
            .build();
    JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
    SignedJWT jwt = new SignedJWT(header, claimsSet);
    try {
      jwt.sign(signer);
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new AppException(e.getMessage());
    }
  }

  public Token createToken(String username) throws AppException {
    try {
      long ONE_MINUTE_IN_MILLIS = 60000; // millisec

      Calendar date = Calendar.getInstance();
      long t = date.getTimeInMillis();
      Date expireDate = new Date(t + (15 * ONE_MINUTE_IN_MILLIS));
      return new Token(Instant.ofEpochSecond(expireDate.getTime()), username);
    } catch (IllegalArgumentException iae) {
      throw new AppException("createToken() caught IllegalArgumentException: " + iae.getMessage());
    }
  }
}
