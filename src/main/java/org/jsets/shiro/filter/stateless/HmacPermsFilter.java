package org.jsets.shiro.filter.stateless;

import cn.hutool.http.HttpStatus;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.util.AbstractCommons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * 基于HMAC（ 散列消息认证码）的无状态认证过滤器--资源验证过滤器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class HmacPermsFilter extends AbstractStatelessFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(HmacPermsFilter.class);

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);

        boolean isAuthenticated = (null == subject || !subject.isAuthenticated()) && isHmacSubmission(request);
        if (isAuthenticated) {
            AuthenticationToken token = createHmacToken(request, response);
            try {
                subject = getSubject(request, response);
                subject.login(token);
                return this.checkPerms(subject, mappedValue);
            } catch (AuthenticationException e) {
                LOGGER.error(request.getRemoteHost() + " HMAC鉴权  " + e.getMessage());
                AbstractCommons.restFailed(WebUtils.toHttp(response), HttpStatus.HTTP_UNAUTHORIZED, e.getMessage());
            }
        }
        return false;
    }

}