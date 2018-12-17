package org.jsets.shiro.filter;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import cn.hutool.core.util.ArrayUtil;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.CollectionUtils;

import com.google.common.collect.Lists;

/**
 * @author: 白振伟
 * @create: 2018年12月17日 19:59:17
 * @Description: 重写RolesAuthorizationFilter，使其继承自JsetsAuthorizationFilter;
 * <br>修改了匹配逻辑，只要当前用户有一个角色满足URL所需角色就放行
 * @version: V1.0
 */
public class JsetsRolesAuthorizationFilter extends AbstractAuthorizationFilter {

    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        Subject subject = getSubject(request, response);
        String[] rolesArray = (String[]) mappedValue;
        if (ArrayUtil.isEmpty(rolesArray)) {
            return true;
        }
        List<String> roles = CollectionUtils.asList(rolesArray);
        boolean[] hasRoles = subject.hasRoles(roles);
        for (boolean hasRole : hasRoles) {
            if (hasRole) {
                return true;
            }
        }
        return false;
    }
}
