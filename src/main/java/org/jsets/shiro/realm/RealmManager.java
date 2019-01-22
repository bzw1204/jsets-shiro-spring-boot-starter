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
package org.jsets.shiro.realm;

import java.util.Collections;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.jsets.shiro.authc.JsetsHmacMatcher;
import org.jsets.shiro.authc.JsetsJwtMatcher;
import org.jsets.shiro.authc.JsetsPasswdMatcher;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.service.impl.DefaultStatelessAccountProvider;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.impl.ShiroCryptoService;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import com.google.common.collect.Lists;

/**
 * REALM 管理器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Getter
@Setter
public class RealmManager {

    private ShiroProperties properties;
    private MessageConfig messages;
    private JsetsPasswdMatcher jsetsPasswdMatcher;
    private ShiroCryptoService shiroCryptoService;
    private ShiroAccountProvider accountProvider;
    private ShiroStatelessAccountProvider statelessAccountProvider;
    private List<Realm> customRealms;
    private CacheDelegator cacheDelegator;

    private List<Realm> statefulRealms = Lists.newLinkedList();
    private List<Realm> statelessRealms = Lists.newLinkedList();
    private List<Realm> cachedRealms = Lists.newLinkedList();


    public void initRealms() {
        if (null == this.statelessAccountProvider) {
            DefaultStatelessAccountProvider defaultStatelessAccountProvider = new DefaultStatelessAccountProvider();
            defaultStatelessAccountProvider.setShiroAccountProvider(accountProvider);
            statelessAccountProvider = defaultStatelessAccountProvider;
        }
        PasswordRealm passwordRealm = new PasswordRealm();
        passwordRealm.setCredentialsMatcher(this.jsetsPasswdMatcher);
        passwordRealm.setAccountProvider(this.accountProvider);
        passwordRealm.setMessages(this.messages);
        if (this.properties.isAuthCacheEnabled()) {
            passwordRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
            passwordRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
            passwordRealm.setCachingEnabled(Boolean.TRUE);
            passwordRealm.setAuthenticationCachingEnabled(Boolean.TRUE);
            passwordRealm.setAuthorizationCachingEnabled(Boolean.TRUE);
            this.addCachedRealms(passwordRealm);
        } else {
            passwordRealm.setCachingEnabled(Boolean.FALSE);
        }
        this.addStatefulRealms(passwordRealm);
        if (this.properties.isHmacEnabled()) {
            JsetsHmacMatcher hmacMatcher = new JsetsHmacMatcher();
            hmacMatcher.setAccountProvider(this.statelessAccountProvider);
            hmacMatcher.setMessages(this.messages);
            hmacMatcher.setCryptoService(this.shiroCryptoService);
            hmacMatcher.setProperties(this.properties);
            hmacMatcher.setCacheDelegator(this.cacheDelegator);
            HmacRealm hmacRealm = new HmacRealm();
            hmacRealm.setAccountProvider(this.statelessAccountProvider);
            hmacRealm.setCredentialsMatcher(hmacMatcher);
            hmacRealm.setCachingEnabled(Boolean.FALSE);
            this.addStatelessRealms(hmacRealm);
        }
        if (properties.isJwtEnabled()) {
            JsetsJwtMatcher jwtMatcher = new JsetsJwtMatcher();
            jwtMatcher.setProperties(this.properties);
            jwtMatcher.setMessages(this.messages);
            jwtMatcher.setCryptoService(this.shiroCryptoService);
            jwtMatcher.setCacheDelegator(this.cacheDelegator);
            JwtRealm jwtRealm = new JwtRealm();
            jwtRealm.setCredentialsMatcher(jwtMatcher);
            jwtRealm.setCachingEnabled(Boolean.FALSE);
            this.addStatelessRealms(jwtRealm);
        }

        this.customRealms.forEach(realm -> {
            if (realm instanceof AuthorizingRealm) {
                AuthorizingRealm authorizingRealm = (AuthorizingRealm) realm;
                if (null == authorizingRealm.getCredentialsMatcher()) {
                    authorizingRealm.setCredentialsMatcher(jsetsPasswdMatcher);
                }
                if (authorizingRealm.isAuthenticationCachingEnabled() && this.properties.isAuthCacheEnabled()) {
                    authorizingRealm.setAuthenticationCacheName(ShiroProperties.CACHE_NAME_AUTHENTICATION);
                }
                if (authorizingRealm.isAuthorizationCachingEnabled() && this.properties.isAuthCacheEnabled()) {
                    authorizingRealm.setAuthorizationCacheName(ShiroProperties.CACHE_NAME_AUTHORIZATION);
                }
                this.cachedRealms.add(authorizingRealm);
                this.statefulRealms.add(authorizingRealm);
            } else {
                this.statefulRealms.add(realm);
            }
        });
    }

    public void addStatefulRealms(Realm statefulRealm) {
        this.statefulRealms.add(statefulRealm);
    }

    public void addStatelessRealms(Realm statelessRealm) {
        this.statelessRealms.add(statelessRealm);
    }

    public void addCachedRealms(Realm cachedRealm) {
        this.cachedRealms.add(cachedRealm);
    }

    /**
     * 获取所有Realms
     *
     * @return Realm集合
     */
    public List<Realm> getAllRealms() {
        List<Realm> realms = Lists.newLinkedList();
        realms.addAll(this.getStatefulRealms());
        realms.addAll(this.getStatelessRealms());
        return Collections.unmodifiableList(realms);
    }
}