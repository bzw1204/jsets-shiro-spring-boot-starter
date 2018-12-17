package org.jsets.shiro.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import lombok.Setter;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.cache.CacheDelegator;
import org.jsets.shiro.config.ShiroProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Strings;

import java.util.regex.Pattern;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:59:56
 * @Description: 保持账号唯一用户登陆
 * @version: V1.0
 */
@Setter
public class KeepOneUserFilter extends AbstractAccessControlFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeepOneUserFilter.class);

    private ShiroProperties properties;
    private SessionManager sessionManager;
    private CacheDelegator cacheDelegate;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        if (!this.properties.isKeepOneEnabled()) {
            return true;
        }
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        if (!subject.isAuthenticated() && !subject.isRemembered()) {
            return this.respondLogin(request, response);
        }
        String account = (String) subject.getPrincipal();
        String loginSessionId = this.cacheDelegate.getKeepUser(account);
        Session currentSession = subject.getSession();
        String currentSessionId = (String) currentSession.getId();

        if (currentSessionId.equals(loginSessionId)) {
            return true;
        } else if (Strings.isNullOrEmpty(loginSessionId)) {
            this.cacheDelegate.putKeepUser(account, currentSessionId);
            return true;
        } else if (null == currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT)) {
            this.cacheDelegate.putKeepUser(account, currentSessionId);
            try {
                Session loginSession = this.sessionManager.getSession(new DefaultSessionKey(loginSessionId));
                if (null != loginSession) {
                    loginSession.setAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT, Boolean.TRUE);
                }
            } catch (SessionException e) {
                LOGGER.warn(e.getMessage());
            }
        }
        if (null != currentSession.getAttribute(ShiroProperties.ATTRIBUTE_SESSION_KICKOUT)) {
            subject.logout();
            return this.respondRedirect(request, response, this.properties.getKickoutUrl());
        }

        return true;
    }

}