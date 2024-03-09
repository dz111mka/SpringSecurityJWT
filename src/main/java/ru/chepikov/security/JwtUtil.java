package ru.chepikov.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;

public class JwtUtil {

    private final static String SECRET = "";
    private final static long VALIDITY_TIME = 3600000;

    public static String generateToken(UserDetails userDetails) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + VALIDITY_TIME);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.ES512, SECRET)
                .compact();
    }

    public static boolean validateToken(String token, UserDetails userDetails) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}