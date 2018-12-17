package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import lombok.Setter;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.model.Account;
import org.jsets.shiro.service.ShiroAccountProvider;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:59:37
 * @Description: 认证过滤，器扩展自UserFilter：增加了针对ajax请求的处理
 * @version: V1.0
 */
public class JsetsUserFilter extends AbstractAccessControlFilter {

    @Setter
    private ShiroAccountProvider accountService;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {

        if (isLoginRequest(request, response)) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            //补齐SESSION中的信息
            if (subject.getPrincipal() != null) {
                Session session = subject.getSession();
                if (null == session.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER)) {
                    String userId = (String) subject.getPrincipal();
                    try {
                        Account account = this.accountService.loadAccount(userId);
                        session.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_CURRENT_USER, account);
                    } catch (AuthenticationException e) {
                        //log
                        subject.logout();
                    }
                }
                return true;
            } else {
                return false;
            }
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return this.respondLogin(request, response);
    }

}