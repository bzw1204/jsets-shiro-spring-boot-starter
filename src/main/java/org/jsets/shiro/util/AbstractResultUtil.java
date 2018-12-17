package org.jsets.shiro.util;

import org.jsets.shiro.response.ResultBean;

/**
 * Description: 统一结果返回工具类
 *
 * @author: 白振伟
 * @create: 2018年12月17日 16:00
 * @version: V1.0
 */
public abstract class AbstractResultUtil {

    public static ResultBean success() {
        return ResultBean.builder().code(1).message("").build();
    }
}
