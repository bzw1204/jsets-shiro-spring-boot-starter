package org.jsets.shiro.token;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * 无状态令牌抽象
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public abstract class AbstractStatelessToken implements AuthenticationToken {

    private static final long serialVersionUID = 6655946030026745372L;

    /**
     * 客户IP
     */
    private String host;

}