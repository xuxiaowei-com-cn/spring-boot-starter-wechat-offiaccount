package org.springframework.security.oauth2.server.authorization.http;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountService;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.Arrays;
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

	/**
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	public static final String AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize"
			+ "?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect";

	/**
	 * 以snsapi_base为 scope 发起的网页授权，是用来获取进入页面的用户的 openid
	 * 的，并且是静默授权并自动跳转到回调页的。用户感知的就是直接进入了回调页（往往是业务页面）
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	public static final String SNSAPI_BASE = "snsapi_base";

	/**
	 * 以snsapi_userinfo为 scope
	 * 发起的网页授权，是用来获取用户的基本信息的。但这种授权需要用户手动同意，并且由于用户同意过，所以无须关注，就可在授权后获取该用户的基本信息。
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	public static final String SNSAPI_USERINFO = "snsapi_userinfo";

	private WeChatOffiaccountService weChatOffiaccountService;

	@Autowired
	public void setWeChatOffiaccountService(WeChatOffiaccountService weChatOffiaccountService) {
		this.weChatOffiaccountService = weChatOffiaccountService;
	}

	/**
	 * 微信公众号授权前缀
	 */
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

			String redirectUri = weChatOffiaccountService.getRedirectUriByAppid(appid);

			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			if (!Arrays.asList(SNSAPI_BASE, SNSAPI_USERINFO).contains(scope)) {
				scope = SNSAPI_BASE;
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
