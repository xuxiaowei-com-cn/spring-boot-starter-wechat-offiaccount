package org.springframework.security.oauth2.server.authorization.http;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * 微信公众号跳转到微信授权页面
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
public class WeChatOffiaccountAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-offiaccount/authorize";

	public static final String AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize"
			+ "?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect";

	private WeChatOffiaccountProperties weChatOffiaccountProperties;

	@Autowired
	public void setWeChatOffiaccountProperties(WeChatOffiaccountProperties weChatOffiaccountProperties) {
		this.weChatOffiaccountProperties = weChatOffiaccountProperties;
	}

	private String prefixUrl = PREFIX_URL;

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String appid = requestUri.replace(prefixUrl + "/", "");

			List<WeChatOffiaccountProperties.WeChatOffiaccount> list = weChatOffiaccountProperties.getList();
			if (list == null) {
				throw new AppidWeChatOffiaccountException("appid 未配置");
			}

			String redirectUri = null;
			boolean include = false;
			for (WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount : list) {
				if (appid.equals(weChatOffiaccount.getAppid())) {
					include = true;
					String redirectUriPrefix = weChatOffiaccount.getRedirectUriPrefix();
					if (StringUtils.hasText(redirectUriPrefix)) {
						redirectUri = UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
					}
					else {
						throw new RedirectUriWeChatOffiaccountException("重定向地址前缀不能为空");
					}
				}
			}

			if (!include) {
				throw new AppidWeChatOffiaccountException("未匹配到 appid");
			}

			String scope = request.getParameter("scope");
			if (!Arrays.asList("snsapi_base", "snsapi_userinfo").contains(scope)) {
				scope = "snsapi_base";
			}

			String state = UUID.randomUUID().toString();
			String url = String.format(AUTHORIZE_URL, appid, redirectUri, scope, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
