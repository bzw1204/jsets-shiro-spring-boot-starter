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

import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.handler.PasswordRetryLimitHandler;
import org.jsets.shiro.service.impl.ShiroCryptoService;

/**
 * 密码匹配器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Setter
public class JsetsPasswdMatcher implements CredentialsMatcher {

    private ShiroProperties properties;
    private MessageConfig messages;
    private PasswordRetryLimitHandler passwordRetryLimitHandler;
    private CacheDelegator cacheDelegator;
    private ShiroCryptoService cryptoService;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        String credentials = String.valueOf((char[]) token.getCredentials());
        String account = (String) info.getPrincipals().getPrimaryPrincipal();
        String password = (String) info.getCredentials();
        String encrypted = this.cryptoService.password(credentials);
        if (!password.equals(encrypted)) {
            int passwordMaxRetries = this.properties.getPasswdMaxRetries();
            String errorMsg = this.messages.getMsgAccountPasswordError();
            if (passwordMaxRetries > 0 && null != this.passwordRetryLimitHandler) {
                errorMsg = this.messages.getMsgPasswordRetryError();
                int passwordRetries = this.cacheDelegator.incPasswordRetryCount(account);
                if (passwordRetries >= passwordMaxRetries - 1) {
                    this.passwordRetryLimitHandler.handle(account);
                }
                int remain = passwordMaxRetries - passwordRetries;
                errorMsg = errorMsg.replace("{total}", String.valueOf(passwordMaxRetries))
                        .replace("{remain}", String.valueOf(remain));
            }
            throw new AuthenticationException(errorMsg);
        }
        this.cacheDelegator.cleanPasswordRetryCount(account);
        return true;
    }

}