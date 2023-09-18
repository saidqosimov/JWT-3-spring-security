package com.example.jwtspringsecurity.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider {
    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    private long tokenValidateMillisecondsRemember;
    private long tokenValidateMilliseconds;
    private final Key key;
    private final JwtParser jwtParser;

    public TokenProvider() {
        byte[] keyByte;
        String secret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
        keyByte = Decoders.BASE64.decode(secret);
        key = Keys.hmacShaKeyFor(keyByte);
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
        this.tokenValidateMillisecondsRemember = 1000 * 86400;
        this.tokenValidateMilliseconds = 1000 * 3600;
    }

    public String createToken(Authentication authentication, Boolean rememberMe) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        long now = (new Date()).getTime();
        Date validate;
        if (rememberMe) {
            validate = new Date(now + tokenValidateMillisecondsRemember);
        } else {
            validate = new Date(now + tokenValidateMilliseconds);
        }
        return Jwts
                .builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .signWith(key, SignatureAlgorithm.ES512)
                .setExpiration(validate)
                .compact();
    }

    public boolean validateToken(String jwt) {
        try {
            jwtParser.parseClaimsJwt(jwt);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("ExpiredJwtException");
        } catch (UnsupportedJwtException u) {
            logger.error("UnsupportedJwtException");
        } catch (MalformedJwtException m) {
            logger.error("MalformedJwtException");
        } catch (SignatureException s) {
            logger.error("SignatureException");
        } catch (IllegalArgumentException i) {
            logger.error("IllegalArgumentException");
        }
        return false;
    }

    public Authentication getAuthentication(String jwt) {
        Claims claims = jwtParser.parseClaimsJwt(jwt).getBody();
        Collection<? extends GrantedAuthority> authorities = Arrays
                .stream(claims.get("auth").toString().split(","))
                .filter(auth->!auth.trim().isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        User principal = new User(claims.getSubject(),"",authorities);
        return new UsernamePasswordAuthenticationToken(principal,jwt,authorities);
    }
}
