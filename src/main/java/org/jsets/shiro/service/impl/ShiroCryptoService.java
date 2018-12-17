/*
 * Copyright 2017-2018 the original author(https://github.com/wj596)
 *
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </p>
 */
package org.jsets.shiro.service.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessLogin;
import org.jsets.shiro.util.AbstractCryptoUtil;
import org.springframework.beans.factory.annotation.Autowired;

import javax.xml.bind.DatatypeConverter;

/**
 * 签名\摘要服务
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class ShiroCryptoService {

    @Autowired
    private ShiroProperties shiroProperties;

    /**
     * 生成密码
     *
     * @param plaintext 明文
     * @return
     */
    public String password(String plaintext) {
        return new SimpleHash(this.shiroProperties.getPasswdAlg()
                , plaintext
                , this.shiroProperties.getPasswdSalt()
                , this.shiroProperties.getPasswdIterations()
        ).toHex();
    }

    /**
     * 生成HMAC摘要
     *
     * @param plaintext 明文
     * @return
     */
    public String hmacDigest(String plaintext) {
        return hmacDigest(plaintext, this.shiroProperties.getHmacSecretKey());
    }

    /**
     * 生成HMAC摘要
     *
     * @param plaintext 明文
     * @param appKey
     * @return
     */
    public String hmacDigest(String plaintext, String appKey) {
        return AbstractCryptoUtil.hmacDigest(plaintext, appKey, this.shiroProperties.getHmacAlg());
    }

    /**
     * 验签JWT
     *
     * @param jwt json web token
     * @return
     */
    public StatelessLogin parseJwt(String jwt) {
        return parseJwt(jwt, this.shiroProperties.getJwtSecretKey());
    }

    /**
     * 验签JWT
     *
     * @param jwt json web token
     */
    public StatelessLogin parseJwt(String jwt, String appKey) {
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(appKey))
                .parseClaimsJws(jwt)
                .getBody();


        return StatelessLogin.builder()
                // 令牌ID
                .appId(claims.getSubject())
                // 客户标识
                .tokenId(claims.getId())
                // 签发者
                .issuer(claims.getIssuer())
                // 签发时间
                .issuedAt(claims.getIssuedAt())
                // 接收方
                .audience(claims.getAudience())
                // 访问主张-角色
                .roles(claims.get("roles", String.class))
                // 访问主张-权限
                .perms(claims.get("perms", String.class))
                .build();
    }

}