package org.jsets.shiro.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Description: 返回结果枚举
 *
 * @author: 白振伟
 * @create: 2018年12月17日 16:04
 * @version: V1.0
 */
@Getter
@AllArgsConstructor
public enum ResultEnum {
    /**
     * 成功
     */
    SUCCESS(1, "操作成功"),
    /**
     * 失败
     */
    FAIL(0, "操作失败"),

    /**
     * 异常
     */
    ERROR(-1, "操作异常");

    private Integer code;
    private String name;
}
