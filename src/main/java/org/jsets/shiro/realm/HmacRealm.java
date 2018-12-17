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

import cn.hutool.core.util.StrUtil;
import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.jsets.shiro.consts.NumberConsts;
import org.jsets.shiro.service.ShiroStatelessAccountProvider;
import org.jsets.shiro.token.HmacToken;

import java.util.Set;

import static org.jsets.shiro.consts.EncryptionTypeConsts.HMAC;
import static org.jsets.shiro.realm.PasswordRealm.buildAuthorizationInfo;

/**
 * 基于HMAC（ 散列消息认证码）的控制域
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class HmacRealm extends AuthorizingRealm {

    @Setter
    private ShiroStatelessAccountProvider accountProvider;


    @Override
    public Class<?> getAuthenticationTokenClass() {
        return HmacToken.class;
    }

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 只认证HmacToken
        if (!(token instanceof HmacToken)) {
            return null;
        }
        HmacToken hmacToken = (HmacToken) token;
        String appId = hmacToken.getAppId();
        String digest = hmacToken.getDigest();
        return new SimpleAuthenticationInfo("hmac:{" + appId + "}", digest, this.getName());
    }

    /**
     * 授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String payload = (String) principals.getPrimaryPrincipal();

        boolean isHmac = payload.startsWith(HMAC) && StrUtil.DELIM_START.equals(payload.charAt(NumberConsts.FIVE)) && StrUtil.DELIM_END.equals(payload.charAt(payload.length() - 1));
        if (isHmac) {
            String appId = payload.substring(6, payload.length() - 1);
            Set<String> roles = this.accountProvider.loadRoles(appId);
            Set<String> permissions = this.accountProvider.loadPermissions(appId);
            return buildAuthorizationInfo(roles, permissions);
        }
        return null;
    }

}