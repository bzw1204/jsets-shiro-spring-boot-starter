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

import java.util.Set;

import cn.hutool.core.collection.CollectionUtil;
import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.service.ShiroAccountProvider;

/**
 * 基于用户、名密码的控制域
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class PasswordRealm extends AuthorizingRealm {

    @Setter
    private MessageConfig messages;
    @Setter
    private ShiroAccountProvider accountProvider;

    @Override
    public Class<?> getAuthenticationTokenClass() {
        return UsernamePasswordToken.class;
    }

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        if (null == token.getPrincipal() || null == token.getCredentials()) {
            throw new AuthenticationException(messages.getMsgAccountPasswordEmpty());
        }
        String account = (String) token.getPrincipal();
        Account accountEntity = this.accountProvider.loadAccount(account);
        if (null == accountEntity) {
            throw new AuthenticationException(messages.getMsgAccountNotExist());
        }
        return new SimpleAuthenticationInfo(account, accountEntity.getPassword(), getName());
    }

    /**
     * 授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String account = (String) principals.getPrimaryPrincipal();

        Set<String> roles = this.accountProvider.loadRoles(account);
        Set<String> permissions = this.accountProvider.loadPermissions(account);
        return buildAuthorizationInfo(roles, permissions);
    }

    /**
     * 构建授权对象
     *
     * @param roles       角色
     * @param permissions 权限
     * @return AuthorizationInfo
     */
    public static AuthorizationInfo buildAuthorizationInfo(Set<String> roles, Set<String> permissions) {
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        if (CollectionUtil.isNotEmpty(roles)) {
            info.setRoles(roles);
        }
        if (CollectionUtil.isNotEmpty(permissions)) {
            info.setStringPermissions(permissions);
        }
        return info;
    }

}