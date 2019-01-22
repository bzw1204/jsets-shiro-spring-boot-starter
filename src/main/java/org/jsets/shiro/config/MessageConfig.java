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

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import static org.jsets.shiro.consts.MessageConsts.*;

/**
 * 用户提示信息配置
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class MessageConfig {

    private static class MessagesHolder {
        private static MessageConfig MESSAGES = new MessageConfig();
    }

    static MessageConfig ins() {
        return MessagesHolder.MESSAGES;
    }

    /**
     * 验证码为空
     */
    private String msgCaptchaEmpty = MSG_CAPTCHA_EMPTY;
    /**
     * 验证码错误
     */
    private String msgCaptchaError = MSG_CAPTCHA_ERROR;
    /**
     * 账号密码为空
     */
    private String msgAccountPasswordEmpty = MSG_ACCOUNT_PASSWORD_EMPTY;
    /**
     * 账号不存在
     */
    private String msgAccountNotExist = MSG_ACCOUNT_NOT_EXIST;
    /**
     * 账号异常
     */
    private String msgAccountException = MSG_ACCOUNT_EXCEPTION;
    /**
     * 账号或密码错误
     */
    private String msgAccountPasswordError = MSG_ACCOUNT_PASSWORD_ERROR;
    /**
     * 密码重试错误
     */
    private String msgPasswordRetryError = MSG_PASSWORD_RETRY_ERROR;
    /**
     * 签名无效
     */
    private String msgHmacError = MSG_HMAC_ERROR;
    /**
     * 签名过期
     */
    private String msgHmacTimeout = MSG_HMAC_TIMEOUT;
    /**
     * 令牌无效
     */
    private String msgJwtError = MSG_JWT_ERROR;
    /**
     * 令牌过期
     */
    private String msgJwtTimeout = MSG_JWT_TIMEOUT;
    /**
     * 令牌格式错误
     */
    private String msgJwtMalformed = MSG_JWT_MALFORMED;
    /**
     * 令牌签名无效
     */
    private String msgJwtSignature = MSG_JWT_SIGNATURE;

}