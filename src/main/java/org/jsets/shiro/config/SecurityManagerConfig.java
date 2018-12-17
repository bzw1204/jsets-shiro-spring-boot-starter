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
package org.jsets.shiro.config;

import com.google.common.collect.Lists;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.jsets.shiro.handler.PasswordRetryLimitHandler;
import org.jsets.shiro.service.ShiroAccountProvider;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;

import java.util.List;

/**
 * shiro 组件配置
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Setter
@Getter
@NoArgsConstructor
public class SecurityManagerConfig {

    /**
     * 账号信息提供者
     */
    private ShiroAccountProvider accountProvider;
    /**
     * 设置无状态鉴权(HMAC、JWT)账号信息提供者
     * <br>如果不设置此项无状态鉴权默认使用accountProviderImpl作为账号信息提供者
     */
    private ShiroStatelessAccountProvider statelessAccountProvider;
    /**
     * 密码错误次数超限处理器
     */
    private PasswordRetryLimitHandler passwordRetryLimitHandler;

    /**
     * 设置RememberMe  Cookie的模板
     * <br>如需要定制RememberMe Cookie的name、domain、httpOnly可设置此项
     *
     * @param rememberMeCookie see org.apache.shiro.web.servlet.SimpleCookie
     */
    private SimpleCookie rememberMeCookie;
    /**
     * 设置SessionDAO
     * <br>如果组件提供的session缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制session持久化
     *
     * @param sessionDAO see org.apache.shiro.session.mgt.eis.SessionDAO
     */
    private SessionDAO sessionDAO;
    /**
     * 设置CacheManager
     * <br>如果组件提供的缓存方式(内存、ehcache、redis)无法满足需求，可设置此项定制缓存实现
     *
     * @param cacheManager see org.apache.shiro.cache.CacheManager
     */
    private CacheManager cacheManager;
    private final List<SessionListener> sessionListeners = Lists.newLinkedList();
    private final List<Realm> realms = Lists.newLinkedList();
    private final MessageConfig messages = MessageConfig.ins();

    /**
     * 添加鉴权控制域
     * <br>组件中提供三个控制域
     * <br>PasswordRealm:有状态用户名,密码鉴权控制域
     * <br>HmacRealm:无状态hmac签名鉴权控制域
     * <br>JwtRealm:无状态jwt令牌鉴权控制域
     * <br>如果无法满足需求，可设置此项添加鉴权控制域
     *
     * @param realm
     */
    public void addRealm(Realm realm) {
        this.realms.add(realm);
    }

}