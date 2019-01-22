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
package org.jsets.shiro.model;

import cn.hutool.core.util.StrUtil;
import com.google.common.base.Strings;
import lombok.Getter;
import lombok.Setter;
import org.jsets.shiro.util.AbstractCommons;

/**
 * 基于角色/权限的权限验证规则
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Getter
@Setter
public class RolePermRule extends AbstractAuthorizeRule {

    private static final long serialVersionUID = 1L;
    /**
     * 资源URL
     */
    private String url;
    /**
     * 访问需要的角色列表(多个角色用逗号分开)
     */
    private String needRoles;

    /**
     * 访问需要的权限列表(多个权限用逗号分开)
     */
    private String needPerms;

    @Override
    public StringBuilder toFilterChain() {

        if (Strings.isNullOrEmpty(this.getUrl())) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        if (AbstractAuthorizeRule.RULE_TYPE_DEF == this.getType()) {
            if (!Strings.isNullOrEmpty(this.getNeedRoles())) {
                sb.append(AbstractCommons.FILTER_ROLES + StrUtil.BRACKET_START).append(this.getNeedRoles()).append(StrUtil.BRACKET_END);
            }
            if (!Strings.isNullOrEmpty(this.getNeedPerms())) {
                if (sb.length() > 0) {
                    sb.append(StrUtil.COMMA);
                }
                sb.append(AbstractCommons.FILTER_PERMS + StrUtil.BRACKET_START).append(this.getNeedPerms()).append(StrUtil.BRACKET_END);
            }
        }
        if (AbstractAuthorizeRule.RULE_TYPE_HMAC == this.getType()) {
            if (!Strings.isNullOrEmpty(this.getNeedRoles())) {
                sb.append(AbstractCommons.FILTER_HMAC_ROLES + StrUtil.BRACKET_START).append(this.getNeedRoles()).append(StrUtil.BRACKET_END);
            }
            if (!Strings.isNullOrEmpty(this.getNeedPerms())) {
                if (sb.length() > 0) {
                    sb.append(StrUtil.COMMA);
                }
                sb.append(AbstractCommons.FILTER_HMAC_PERMS + StrUtil.BRACKET_START).append(this.getNeedPerms()).append(StrUtil.BRACKET_END);
            }
            if (sb.length() == 0) {
                sb.append(AbstractCommons.FILTER_HMAC);
            }
        }
        if (AbstractAuthorizeRule.RULE_TYPE_JWT == this.getType()) {
            if (!Strings.isNullOrEmpty(this.getNeedRoles())) {
                sb.append(AbstractCommons.FILTER_JWT_ROLES + StrUtil.BRACKET_START).append(this.getNeedRoles()).append(StrUtil.BRACKET_END);
            }
            if (!Strings.isNullOrEmpty(this.getNeedPerms())) {
                if (sb.length() > 0) {
                    sb.append(StrUtil.COMMA);
                }
                sb.append(AbstractCommons.FILTER_JWT_ROLES + StrUtil.BRACKET_START).append(this.getNeedPerms()).append(StrUtil.BRACKET_END);
            }
            if (sb.length() == 0) {
                sb.append(AbstractCommons.FILTER_JWT);
            }
        }
        return sb.length() > 0 ? sb : null;
    }

    @Override
    public String toString() {
        return "RolePermRule [url=" + url + ", needRoles=" + needRoles + ", needPerms=" + needPerms + StrUtil.BRACKET_END;
    }

}