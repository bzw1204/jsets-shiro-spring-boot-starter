package org.jsets.shiro.util;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.StrUtil;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.Date;
import java.util.UUID;

/**
 * 安全加密相关工具类
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public abstract class AbstractCryptoUtil {

    /******* HMAC 加密算法名称 *******/

    /**
     * 128位
     */
    public static final String HMAC_MD5 = "HmacMD5";
    /**
     * 126
     */
    public static final String HMAC_SHA1 = "HmacSHA1";
    /**
     * 256
     */
    public static final String HMAC_SHA256 = "HmacSHA256";
    /**
     * 512
     */
    public static final String HMAC_SHA512 = "HmacSHA512";

    /**
     * JWT签发令牌
     *
     * @param jwtSecretKey 令牌ID
     * @param subject      用户ID
     * @param issuer       签发人
     * @param period       有效时间(毫秒)c
     * @param roles        访问主张-角色
     * @param permissions  访问主张-权限
     * @param algorithm    加密算法(SignatureAlgorithm是enum)
     * @return
     */
    public static String issueJwt(String jwtSecretKey, String subject, String issuer, Long period, String roles, String permissions, SignatureAlgorithm algorithm) {

        // 当前时间戳(精确到毫秒)
        long currentTimeMillis = System.currentTimeMillis();
        // 秘钥
        byte[] secretKeyBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);
        JwtBuilder jwt = Jwts.builder();
        jwt.setId(UUID.randomUUID().toString());
        // 用户名
        jwt.setSubject(subject);
        // 签发者
        if (StrUtil.isNotBlank(issuer)) {
            jwt.setIssuer(issuer);
        }
        // 签发时间
        jwt.setIssuedAt(new Date(currentTimeMillis));
        // 有效时间
        if (null != period) {
            Date expiration = new Date(currentTimeMillis + period);
            jwt.setExpiration(expiration);
        }
        // 访问主张-角色
        if (StrUtil.isNotBlank(roles)) {
            jwt.claim("roles", roles);
        }
        // 访问主张-权限
        if (StrUtil.isNotBlank(permissions)) {
            jwt.claim("perms", permissions);
        }
        jwt.compressWith(CompressionCodecs.DEFLATE);
        jwt.signWith(algorithm, secretKeyBytes);
        return jwt.compact();
    }

    /**
     * 生成HMAC摘要
     *
     * @param plaintext 明文
     * @param secretKey 安全秘钥
     * @param algName   算法名称
     * @return 摘要
     */
    public static String hmacDigest(String plaintext, String secretKey, String algName) {
        try {
            Mac mac = Mac.getInstance(algName);
            byte[] secretByte = secretKey.getBytes();
            byte[] dataBytes = plaintext.getBytes();
            SecretKey secret = new SecretKeySpec(secretByte, algName);
            mac.init(secret);
            byte[] doFinal = mac.doFinal(dataBytes);
            return ArrayUtil.toString(doFinal);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}