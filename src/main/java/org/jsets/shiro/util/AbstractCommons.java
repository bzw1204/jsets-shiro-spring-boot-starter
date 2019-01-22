package org.jsets.shiro.util;

import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.jsonwebtoken.impl.TextCodec;
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver;
import io.jsonwebtoken.lang.Assert;
import lombok.Cleanup;
import org.jsets.shiro.config.ShiroProperties;
import org.jsets.shiro.consts.NumberConsts;
import org.jsets.shiro.response.ResultBean;
import org.jsets.shiro.token.AbstractStatelessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * 辅助工具类
 *
 * @author wangjie (https://github.com/wj596)
 * @date 2016年6月31日
 */
@SuppressWarnings(value = "unchecked")
public abstract class AbstractCommons {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractCommons.class);

    public static final String JCAPTCHA_URL = "/jcaptcha.jpg";
    public static final String FILTER_ANON = "anon";
    public static final String FILTER_AUTHC = "authc";
    public static final String FILTER_JCAPTCHA = "jcaptcha";

    public static final String FILTER_ROLES = "roles";
    public static final String FILTER_PERMS = "perms";
    public static final String FILTER_USER = "user";

    public static final String FILTER_KEEP_ONE = "keepOne";

    public static final String FILTER_FORCE_LOGOUT = "forceLogout";

    public static final String FILTER_HMAC = "hmac";
    public static final String FILTER_HMAC_ROLES = "hmacRoles";
    public static final String FILTER_HMAC_PERMS = "hmacPerms";

    public static final String FILTER_JWT = "jwt";
    public static final String FILTER_JWT_ROLES = "jwtRoles";
    public static final String FILTER_JWT_PERMS = "jwtPerms";

    public static final short CACHE_TYPE_MAP = 0;
    public static final short CACHE_TYPE_EHCACHE = 1;
    public static final short CACHE_TYPE_REDIS = 2;
    public static final short CACHE_TYPE_CUSTOM = 3;
    public static final short CACHE_TYPE_SPRING = 4;

    public static final String REMEMBER_ME_COOKIE_NAME = "rememberMeCookie";


    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static CompressionCodecResolver CODEC_RESOLVER = new DefaultCompressionCodecResolver();

    /**
     * 判断是否AJAX请求
     *
     * @param request
     * @return
     */
    public static boolean isAjax(HttpServletRequest request) {
        return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
    }

    /**
     * REST失败响应
     *
     * @param response
     * @param code
     * @param message
     */
    public static void restFailed(HttpServletResponse response, Integer code, String message) {
        respondJson(response, HttpServletResponse.SC_BAD_REQUEST, code, message);
    }

    /**
     * AJAX成功响应
     *
     * @param response
     * @param code
     * @param message
     */
    public static void ajaxSucceed(HttpServletResponse response, Integer code, String message) {
        respondJson(response, HttpServletResponse.SC_OK, code, message);
    }

    /**
     * AJAX失败响应
     *
     * @param response
     * @param respondStatus
     * @param code
     * @param message
     */
    public static void ajaxFailed(HttpServletResponse response, int respondStatus, Integer code, String message) {
        respondJson(response, respondStatus, code, message);
    }

    /**
     * JSON响应
     *
     * @param response
     * @param respondStatus 相应状态
     * @param code          相应码
     * @param message       相应消息
     */
    private static void respondJson(HttpServletResponse response, int respondStatus, Integer code, String message) {
        response.setStatus(respondStatus);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        try {
            @Cleanup PrintWriter out = response.getWriter();
            String json = new ObjectMapper().writeValueAsString(ResultBean.builder().code(code).message(message).build());
            out.write(json);
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * 设置信息
     *
     * @param request
     * @param message
     */
    public static void setAuthMessage(ServletRequest request, String message) {
        request.setAttribute(ShiroProperties.ATTRIBUTE_REQUEST_AUTH_MESSAGE, message);
    }

    /**
     * 以逗号分割字符串进SET
     *
     * @param str
     * @return
     */
    public static Set<String> split(String str) {
        return split(str, StrUtil.COMMA);
    }

    /**
     * 分割字符串并放入Set集合
     *
     * @param str
     * @param separator
     * @return
     */
    public static Set<String> split(String str, String separator) {
        return StrUtil.splitTrim(str, separator).parallelStream().collect(toSet());
    }

    /**
     * 是否无状态令牌
     */
    public static boolean isStatelessToken(Object token) {
        return token instanceof AbstractStatelessToken;
    }

    /**
     * 对象转JSON
     */
    public static String toJson(Object object) {
        try {
            return MAPPER.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * JSON转对象
     */
    public static <T> T fromJson(String json, Class<T> valueType) {
        try {
            return MAPPER.readValue(json, valueType);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * JSON转对象
     */
    public static boolean hasLen(String string) {
        return !Strings.isNullOrEmpty(string);
    }

    /**
     * 解析JWT的Payload
     */
    public static String parseJwtPayload(String jwt) {
        Assert.hasText(jwt, "JWT String argument cannot be null or empty.");
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedPayload = null;
        String base64UrlEncodedDigest = null;
        int delimiterCount = NumberConsts.ZERO;
        StringBuilder sb = new StringBuilder(128);
        for (char c : jwt.toCharArray()) {
            if (c == StrUtil.C_DOT) {
                CharSequence tokenSeq = io.jsonwebtoken.lang.Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == NumberConsts.ZERO) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedPayload = token;
                }

                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        if (delimiterCount != NumberConsts.TWO) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }
        if (sb.length() > NumberConsts.ZERO) {
            base64UrlEncodedDigest = sb.toString();
        }
        if (base64UrlEncodedPayload == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a body/payload.");
        }
        // =============== Header =================
        Header header = null;
        CompressionCodec compressionCodec = null;
        if (base64UrlEncodedHeader != null) {
            String origValue = TextCodec.BASE64URL.decodeToString(base64UrlEncodedHeader);
            Map<String, Object> m = readValue(origValue);
            if (base64UrlEncodedDigest != null) {
                header = new DefaultJwsHeader(m);
            } else {
                header = new DefaultHeader(m);
            }
            compressionCodec = CODEC_RESOLVER.resolveCompressionCodec(header);
        }
        // =============== Body =================
        String payload;
        if (compressionCodec != null) {
            byte[] decompressed = compressionCodec.decompress(TextCodec.BASE64URL.decode(base64UrlEncodedPayload));
            payload = new String(decompressed, io.jsonwebtoken.lang.Strings.UTF_8);
        } else {
            payload = TextCodec.BASE64URL.decodeToString(base64UrlEncodedPayload);
        }
        return payload;
    }

    public static Map<String, Object> readValue(String val) {
        try {
            return MAPPER.readValue(val, Map.class);
        } catch (IOException e) {
            throw new MalformedJwtException("Unable to read JSON value: " + val, e);
        }
    }
}