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

import java.util.Arrays;
import java.util.Set;

import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.model.DefaultAccount;
import com.google.common.collect.Sets;
import org.jsets.shiro.service.ShiroAccountProvider;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 16:45:03
 * @Description: 默认的账号服务
 * @version: V1.0
 */
@Setter
public class DefaultAccountProvider implements ShiroAccountProvider {

    private ShiroCryptoService shiroCryptoService;

    public static final String DEFAULT_ACCOUNT = "test";
    public static final String DEFAULT_ROLES = "testRole";
    public static final String DEFAULT_PERMS = "testPerm";

    @Override
    public Account loadAccount(String account) throws AuthenticationException {
        if (!DEFAULT_ACCOUNT.equals(account)) {
            throw new AuthenticationException("用户名或密码错误");
        }
        return new DefaultAccount(account, this.shiroCryptoService.password(DEFAULT_ACCOUNT));
    }

    @Override
    public Set<String> loadRoles(String account) {
        return Sets.newHashSet(Arrays.asList(DEFAULT_ROLES));
    }

    @Override
    public Set<String> loadPermissions(String account) {
        return Sets.newHashSet(Arrays.asList(DEFAULT_PERMS));
    }

}