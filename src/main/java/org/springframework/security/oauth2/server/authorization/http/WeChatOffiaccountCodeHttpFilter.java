package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.exception.SecretWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 微信公众号授权码接收服务
 *
 * @see <a href=
 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">网页授权</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class WeChatOffiaccountCodeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-offiaccount/code";

	public static final String ACCESS_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={appid}&secret={secret}&code={code}&grant_type=authorization_code";

	private String prefixUrl = PREFIX_URL;

	private WeChatOffiaccountProperties weChatOffiaccountProperties;

	@Autowired
	public void setWeChatOffiaccountProperties(WeChatOffiaccountProperties weChatOffiaccountProperties) {
		this.weChatOffiaccountProperties = weChatOffiaccountProperties;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");
			String code = request.getParameter("code");
			String state = request.getParameter("state");

			response.sendRedirect("/oauth2/token?grant_type=wechat-offiaccount&appid=" + appid + "&code=" + code);

//			List<WeChatOffiaccountProperties.WeChatOffiaccount> list = weChatOffiaccountProperties.getList();
//			if (list == null) {
//				throw new AppidWeChatOffiaccountException("appid 未配置");
//			}
//
//			String secret = null;
//			boolean include = false;
//			for (WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount : list) {
//				if (appid.equals(weChatOffiaccount.getAppid())) {
//					include = true;
//					secret = weChatOffiaccount.getSecret();
//					if (!StringUtils.hasText(secret)) {
//						throw new SecretWeChatOffiaccountException("secret 不能为空");
//					}
//				}
//			}
//
//			if (!include) {
//				throw new AppidWeChatOffiaccountException("未匹配到 appid");
//			}
//
//			RestTemplate restTemplate = new RestTemplate();
//			Map<String, String> uriVariables = new HashMap<>(8);
//			uriVariables.put("appid", appid);
//			uriVariables.put("secret", secret);
//			uriVariables.put("code", code);
//			String forObject = restTemplate.getForObject(ACCESS_TOKEN_URL, String.class, uriVariables);
//
//			log.info(forObject);

			return;
		}

		super.doFilter(request, response, chain);
	}

}
