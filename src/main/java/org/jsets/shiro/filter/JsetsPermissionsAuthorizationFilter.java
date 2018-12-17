package org.jsets.shiro.filter;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import cn.hutool.core.util.ArrayUtil;
import org.apache.shiro.subject.Subject;
import org.jsets.shiro.model.AbstractAuthorizeRule;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:59:02
 * @Description: 重写PermissionsAuthorizationFilter，使其继承自JsetsAuthorizationFilter
 * @version: V1.0
 */
public class JsetsPermissionsAuthorizationFilter extends AbstractAuthorizationFilter {

    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        Subject subject = getSubject(request, response);
        String[] perms = (String[]) mappedValue;
        boolean isPermitted = true;
        if (ArrayUtil.isNotEmpty(perms)) {
            if (perms.length == 1) {
                if (!subject.isPermitted(perms[0])) {
                    isPermitted = false;
                }
            } else {
                if (!subject.isPermittedAll(perms)) {
                    isPermitted = false;
                }
            }
        }
        return isPermitted;
    }

}
