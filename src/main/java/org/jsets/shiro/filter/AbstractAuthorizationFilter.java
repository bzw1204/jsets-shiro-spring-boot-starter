package org.jsets.shiro.filter;

import cn.hutool.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.util.AbstractCommons;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.jsets.shiro.consts.MessageConsts.REST_MESSAGE_AUTH_FORBIDDEN;
import static org.jsets.shiro.consts.MessageConsts.REST_MESSAGE_AUTH_UNAUTHORIZED;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:58:22
 * @Description: 抽象权限过滤器, 扩展自AuthorizationFilter增加了针对ajax请求的处理
 * @version: V1.0
 */
public abstract class AbstractAuthorizationFilter extends AuthorizationFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        Subject subject = getSubject(request, response);
        //未认证
        if (null == subject.getPrincipal()) {
            if (AbstractCommons.isAjax(WebUtils.toHttp(request))) {
                AbstractCommons.ajaxFailed(WebUtils.toHttp(response)
                        , HttpServletResponse.SC_UNAUTHORIZED
                        , HttpStatus.HTTP_UNAUTHORIZED
                        , REST_MESSAGE_AUTH_UNAUTHORIZED);
            }
            saveRequestAndRedirectToLogin(request, response);
            //未授权
        } else {
            if (AbstractCommons.isAjax(WebUtils.toHttp(request))) {
                AbstractCommons.ajaxFailed(WebUtils.toHttp(response)
                        , HttpServletResponse.SC_FORBIDDEN
                        , HttpStatus.HTTP_UNAUTHORIZED
                        , REST_MESSAGE_AUTH_FORBIDDEN);
            } else {
                String unauthorizedUrl = getUnauthorizedUrl();
                if (StringUtils.hasText(unauthorizedUrl)) {
                    WebUtils.issueRedirect(request, response, unauthorizedUrl);
                } else {
                    WebUtils.toHttp(response).sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
        }
        return Boolean.FALSE;
    }

}