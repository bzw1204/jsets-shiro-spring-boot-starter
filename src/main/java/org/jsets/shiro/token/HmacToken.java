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
package org.jsets.shiro.token;

import lombok.Getter;
import lombok.Setter;

/**
 * HMAC(哈希消息认证码)令牌
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Getter
@Setter
public class HmacToken extends AbstractStatelessToken {

    private static final long serialVersionUID = -7838912794581842158L;

    /**
     * 客户标识
     */
    private String appId;
    /**
     * 时间戳
     */
    private String timestamp;
    /**
     * 待核验字符串
     */
    private String baseString;
    /**
     * 消息摘要
     */
    private String digest;

    public HmacToken(String host, String appId, String timestamp, String baseString, String digest) {
        super(host);
        this.appId = appId;
        this.timestamp = timestamp;
        this.baseString = baseString;
        this.digest = digest;
    }

    @Override
    public Object getPrincipal() {
        return this.appId;
    }

    @Override
    public Object getCredentials() {
        return Boolean.TRUE;
    }
}