package com.ai.mcp.config;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

/** 测试侧模拟控制台: 签名 / 私钥加密 / 现签证书 */
final class TlsTestSupport {

    private TlsTestSupport() {
    }

    static String encrypt(String secret, String nodeId, long version, byte[] iv, String plain) throws Exception {
        Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
        ci.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(TlsManager.tlsKey(secret), "AES"), new GCMParameterSpec(128, iv));
        ci.updateAAD((nodeId + "\n" + version).getBytes(StandardCharsets.UTF_8));
        byte[] ct = ci.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] all = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, all, 0, iv.length);
        System.arraycopy(ct, 0, all, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(all);
    }

    static String sign(String secret, String nodeId, TlsManager.AuthConf c) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(TlsManager.payload(nodeId, c).getBytes(StandardCharsets.UTF_8)));
    }

    static Map<String, Object> toMap(TlsManager.AuthConf c) {
        Map<String, Object> m = new HashMap<>();
        m.put("authType", c.authType());
        m.put("authToken", c.authToken());
        m.put("authVersion", c.authVersion());
        m.put("serverCert", c.serverCert());
        m.put("serverKeyEnc", c.serverKeyEnc());
        m.put("clientCaCert", c.clientCaCert());
        return m;
    }

    /** 控制台下发: 加密私钥 + 签名, 返回 {authConf, authSign} */
    static Map<String, Object> issue(String secret, String nodeId, String type, String token, long version,
                                     String certPem, String keyPem, String caPem) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        String enc = keyPem == null ? null : encrypt(secret, nodeId, version, iv, keyPem);
        TlsManager.AuthConf c = new TlsManager.AuthConf(type, token, version, certPem, enc, caPem);
        Map<String, Object> data = new HashMap<>();
        data.put("authConf", toMap(c));
        data.put("authSign", sign(secret, nodeId, c));
        return data;
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        return g.generateKeyPair();
    }

    static X509Certificate cert(String cn, PublicKey pub, String issuerCn, PrivateKey signer, boolean ca) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=" + issuerCn),
                BigInteger.valueOf(now).add(BigInteger.valueOf(System.nanoTime() & 0xffff)),
                new Date(now - 60_000), new Date(now + 86_400_000), new X500Name("CN=" + cn), pub);
        if (ca) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        String alg = "RSA".equals(signer.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
        return new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder(alg).build(signer)));
    }

    static String pem(X509Certificate c) throws Exception {
        return pem("CERTIFICATE", c.getEncoded());
    }

    static String pem(PrivateKey k) {
        return pem("PRIVATE KEY", k.getEncoded());
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
