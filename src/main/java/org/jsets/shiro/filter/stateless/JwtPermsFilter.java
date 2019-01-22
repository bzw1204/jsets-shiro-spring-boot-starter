package org.jsets.shiro.filter.stateless;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import cn.hutool.http.HttpStatus;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.util.AbstractCommons;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 基于JWT标准的无状态过滤器--资源验证过滤器
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
public class JwtPermsFilter extends AbstractStatelessFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtPermsFilter.class);

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        boolean isAuthenticated = (null == subject || !subject.isAuthenticated()) && isJwtSubmission(request);
        if (isAuthenticated) {
            AuthenticationToken token = createJwtToken(request, response);
            try {
                subject = getSubject(request, response);
                subject.login(token);
                return this.checkPerms(subject, mappedValue);
            } catch (AuthenticationException e) {
                LOGGER.error(request.getRemoteHost() + " JWT鉴权  " + e.getMessage());
                AbstractCommons.restFailed(WebUtils.toHttp(response), HttpStatus.HTTP_UNAUTHORIZED, e.getMessage());
            }
        }
        return Boolean.FALSE;
    }
}
