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
package org.jsets.shiro.authc;

import com.google.common.base.Strings;
import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.StatelessLogin;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.jsets.shiro.service.impl.ShiroCryptoService;
import org.jsets.shiro.token.HmacToken;
import org.jsets.shiro.util.AbstractCommons;

import java.util.Date;
import java.util.Optional;

import static org.jsets.shiro.consts.MessageConsts.MSG_BURNED_TOKEN;
import static org.jsets.shiro.consts.MessageConsts.MSG_NO_SECRET_KEY;

/**
 * HMAC签名匹配器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Setter
public class JsetsHmacMatcher implements CredentialsMatcher {

    private ShiroProperties properties;
    private MessageConfig messages;
    private ShiroCryptoService cryptoService;
    private ShiroStatelessAccountProvider accountProvider;
    private CacheDelegator cacheDelegator;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        HmacToken hmacToken = (HmacToken) token;
        String appId = hmacToken.getAppId();
        String digest = (String) info.getCredentials();
        String serverDigest = null;
        if (this.properties.isHmacBurnEnabled() && this.cacheDelegator.cutBurnedToken(digest)) {
            throw new AuthenticationException(MSG_BURNED_TOKEN);
        }
        if (AbstractCommons.hasLen(this.properties.getHmacSecretKey())) {
            serverDigest = this.cryptoService.hmacDigest(hmacToken.getBaseString());
        } else {
            String appKey = Optional.ofNullable(accountProvider.loadAppKey(appId)).orElseThrow(() -> new AuthenticationException(MSG_NO_SECRET_KEY));
            serverDigest = this.cryptoService.hmacDigest(hmacToken.getBaseString(), appKey);
        }

        if (Strings.isNullOrEmpty(serverDigest)) {
            throw new AuthenticationException(this.messages.getMsgHmacError());
        }
        if (!serverDigest.equals(digest)) {
            throw new AuthenticationException(this.messages.getMsgHmacError());
        }
        Long currentTimeMillis = System.currentTimeMillis();
        Long tokenTimestamp = Long.valueOf(hmacToken.getTimestamp());
        // 数字签名超时失效
        if ((currentTimeMillis - tokenTimestamp) > this.properties.getHmacPeriod()) {
            throw new AuthenticationException(this.messages.getMsgHmacTimeout());
        }
        // 检查账号
        boolean checkAccount = this.accountProvider.checkAccount(appId);
        if (!checkAccount) {
            throw new AuthenticationException(this.messages.getMsgAccountException());
        }
        StatelessLogin statelessAccount = new StatelessLogin();
        statelessAccount.setTokenId(hmacToken.getDigest());
        statelessAccount.setAppId(hmacToken.getAppId());
        statelessAccount.setHost(hmacToken.getHost());
        statelessAccount.setIssuedAt(new Date(tokenTimestamp));
        AbstractStatelessLocals.setAccount(statelessAccount);
        return true;
    }

}