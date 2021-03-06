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

import com.google.common.base.Strings;
import lombok.Getter;
import lombok.Setter;

/**
 * 自由定制的权限验证规则
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class CustomRule extends AbstractAuthorizeRule {

    private static final long serialVersionUID = 1L;
    /**
     * 资源URL
     */
    @Getter
    @Setter
    private String url;
    /**
     * 过滤规则
     */
    @Getter
    @Setter
    private String rule;


    @Override
    public StringBuilder toFilterChain() {
        if (Strings.isNullOrEmpty(this.getUrl())) {
            return null;
        }
        if (Strings.isNullOrEmpty(this.getRule())) {
            return null;
        }
        return new StringBuilder(this.getRule());
    }

}