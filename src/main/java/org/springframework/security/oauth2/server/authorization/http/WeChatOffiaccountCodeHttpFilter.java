package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
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

	public static final String TOKEN_URL = "/oauth2/token?grant_type={grant_type}&appid={appid}&code={code}&state={state}&client_id={client_id}&client_secret={client_secret}";

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
			String grantType = "wechat_offiaccount";

			String clientId = null;
			String clientSecret = null;
			String tokenUrlPrefix = null;
			String scope = null;
			List<WeChatOffiaccountProperties.WeChatOffiaccount> list = weChatOffiaccountProperties.getList();
			if (list == null) {
				throw new AppidWeChatOffiaccountException("appid 未配置");
			}

			boolean include = false;
			for (WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount : list) {
				if (appid.equals(weChatOffiaccount.getAppid())) {
					include = true;
					clientId = weChatOffiaccount.getClientId();
					clientSecret = weChatOffiaccount.getClientSecret();
					tokenUrlPrefix = weChatOffiaccount.getTokenUrlPrefix();
					scope = weChatOffiaccount.getScope();
				}
			}

			if (!include) {
				throw new AppidWeChatOffiaccountException("未匹配到 appid");
			}

			RestTemplate restTemplate = new RestTemplate();
			Map<String, String> uriVariables = new HashMap<>(8);
			uriVariables.put("grant_type", grantType);
			uriVariables.put("appid", appid);
			uriVariables.put("code", code);
			uriVariables.put("state", state);
			uriVariables.put("scope", scope);
			uriVariables.put("client_id", clientId);
			uriVariables.put("client_secret", clientSecret);

			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.setContentType(MediaType.APPLICATION_JSON);
			HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

			@SuppressWarnings("all")
			Map<String, String> post = restTemplate.postForObject(tokenUrlPrefix + TOKEN_URL, httpEntity, Map.class,
					uriVariables);

			String accessToken = post.get("access_token");

			response.sendRedirect("http://a.com?access_token=" + accessToken);

			return;
		}

		super.doFilter(request, response, chain);
	}

}
