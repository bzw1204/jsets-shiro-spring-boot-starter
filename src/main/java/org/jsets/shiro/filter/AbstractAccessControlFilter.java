package org.jsets.shiro.filter;

import cn.hutool.http.HttpStatus;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.jsets.shiro.config.MessageConfig;
import org.jsets.shiro.util.AbstractCommons;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:58:02
 * @Description: 抽象认证过滤器, 扩展自AccessControlFilter增加了针对ajax请求的处理。
 * @version: V1.0
 */
public abstract class AbstractAccessControlFilter extends AccessControlFilter {

    /**
     * 定位到登陆界面，返回false过滤器链停止
     */
    protected boolean respondLogin(ServletRequest request, ServletResponse response) throws IOException {
        if (AbstractCommons.isAjax(WebUtils.toHttp(request))) {
            AbstractCommons.ajaxFailed(WebUtils.toHttp(response)
                    , HttpServletResponse.SC_UNAUTHORIZED
                    , HttpStatus.HTTP_UNAUTHORIZED
                    , MessageConfig.REST_MESSAGE_AUTH_UNAUTHORIZED);
            // 过滤器链停止
            return false;
        }
        saveRequestAndRedirectToLogin(request, response);
        return false;
    }

    /**
     * 定位到指定界面，返回false过滤器链停止
     */
    protected boolean respondRedirect(ServletRequest request, ServletResponse response, String redirectUrl) throws IOException {
        WebUtils.issueRedirect(request, response, redirectUrl);
        return false;
    }

}