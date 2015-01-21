package com.mechanitis.jitter;

import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.Random;

import static java.net.URLEncoder.encode;

public class OAuth {
    private static final String HMAC_SHA1 = "HMAC-SHA1";
    private long nonce;
    private long timestampInSeconds;

    //from properties file
    private String accessTokenSecret;
    private String token;
    private String consumerKey;
    private String consumerSecret;

    public OAuth() {
        this.timestampInSeconds = System.currentTimeMillis() / 1000;
        this.nonce = timestampInSeconds + (new Random()).nextInt();
        loadProperties();
    }

    private void loadProperties() {
        Properties prop = new Properties();
        InputStream in = getClass().getResourceAsStream("/oauth.properties");
        try {
            prop.load(in);
            in.close();
        } catch (IOException e) {
            throw new ConnectionException("Could not load oauth.properties", e);
        }
        consumerSecret = prop.getProperty("consumerSecret");
        accessTokenSecret = prop.getProperty("accessTokenSecret");
        token = prop.getProperty("token");
        consumerKey = prop.getProperty("consumerKey");
    }

    private String getBaseParams() {
        return "oauth_consumer_key=" + consumerKey + "&" +
               "oauth_nonce=" + String.valueOf(nonce) + "&" +
               "oauth_signature_method=" + HMAC_SHA1 + "&" +
               "oauth_timestamp=" + String.valueOf(timestampInSeconds) + "&" +
               "oauth_token=" + token + "&" +
               "oauth_version=1.0";
    }

    public String getAuthParams() {
        return "oauth_consumer_key=\"" + consumerKey + "\", " +
               "oauth_nonce=\"" + String.valueOf(nonce) + "\", " +
               "oauth_signature_method=\"" + HMAC_SHA1 + "\", " +
               "oauth_timestamp=\"" + String.valueOf(timestampInSeconds) + "\", " +
               "oauth_token=\"" + token + "\", " +
               "oauth_version=\"1.0\"";
    }

    private String getBaseString() {
        try {
            StringBuilder base = new StringBuilder("GET")
                    .append("&")
                    .append(encode("https://stream.twitter.com/1.1/statuses/sample.json", "UTF-8"))
                    .append("&")
                    .append(encode(getBaseParams(), "UTF-8"));
            return base.toString();
        } catch (UnsupportedEncodingException e) {
            throw new ConnectionException(e);
        }
    }

    public String generateSignature() {
        byte[] byteHMAC;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");

            String oauthSignature = encode(consumerSecret, "UTF-8")
                                    + "&" + encode(accessTokenSecret, "UTF-8");

            SecretKeySpec spec = new SecretKeySpec(oauthSignature.getBytes(), HMAC_SHA1);
            mac.init(spec);
            byteHMAC = mac.doFinal(getBaseString().getBytes());
            return encode(new BASE64Encoder().encode(byteHMAC), "UTF-8");
        } catch (InvalidKeyException ike) {
            throw new ConnectionException("Failed initialize \"Message Authentication Code\" (MAC)", ike);
        } catch (NoSuchAlgorithmException nsae) {
            throw new ConnectionException("Failed to get HmacSHA1 \"Message Authentication Code\" (MAC)", nsae);
        } catch (UnsupportedEncodingException e) {
            throw new ConnectionException("Failed to get encoder", e);
        }
    }
}
