package org.jsets.shiro.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Description: 统一结果返回
 *
 * @author: 白振伟
 * @create: 2018年12月17日 15:58
 * @version: V1.0
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResultBean {

    /**
     * 相应码
     */
    private Integer code;

    /**
     * 相应消息
     */
    private String message;

    /**
     * 相应数据
     */
    private Object data;
}
