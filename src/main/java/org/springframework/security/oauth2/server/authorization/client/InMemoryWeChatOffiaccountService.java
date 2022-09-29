package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.WeChatOffiaccountAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatOffiaccountParameterNames;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectWeChatOffiaccountException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatOffiaccountEndpointUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 微信公众号 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryWeChatOffiaccountService implements WeChatOffiaccountService {

	private final WeChatOffiaccountProperties weChatOffiaccountProperties;

	public InMemoryWeChatOffiaccountService(WeChatOffiaccountProperties weChatOffiaccountProperties) {
		this.weChatOffiaccountProperties = weChatOffiaccountProperties;
	}

	/**
	 * 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID(公众号ID)
	 * @param code 授权码，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0">第一步：用户同意授权，获取code</a>
	 * @param openid 用户唯一标识，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param credentials 证书
	 * @param unionid 多账户用户唯一标识，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param accessToken 授权凭证，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param refreshToken 刷新凭证，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param expiresIn 过期时间，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param scope {@link OAuth2ParameterNames#SCOPE}，授权范围，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @return 返回 认证信息
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(weChatOffiaccountProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(openid, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		WeChatOffiaccountAuthenticationToken authenticationToken = new WeChatOffiaccountAuthenticationToken(authorities,
				clientPrincipal, principal, user, additionalParameters, details, appid, code, openid);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

	/**
	 * 根据 AppID(公众号ID)、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID(公众号ID)，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @param code 授权码，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html#0">第一步：用户同意授权，获取code</a>
	 * @param accessTokenUrl <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">通过
	 * code 换取网页授权 access_token 的 URL</a>
	 * @return 返回 微信授权结果
	 */
	@Override
	public WeChatOffiaccountTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl) {
		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2WeChatOffiaccountParameterNames.APPID, appid);

		String secret = getSecretByAppid(appid);

		uriVariables.put(OAuth2WeChatOffiaccountParameterNames.SECRET, secret);
		uriVariables.put(OAuth2WeChatOffiaccountParameterNames.CODE, code);

		RestTemplate restTemplate = new RestTemplate();

		String forObject = restTemplate.getForObject(accessTokenUrl, String.class, uriVariables);

		WeChatOffiaccountTokenResponse weChatOffiaccountTokenResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			weChatOffiaccountTokenResponse = objectMapper.readValue(forObject, WeChatOffiaccountTokenResponse.class);
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatOffiaccountEndpointUtils.ERROR_CODE,
					"使用微信公众号授权code：" + code + " 获取Token异常", OAuth2WeChatOffiaccountEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		String openid = weChatOffiaccountTokenResponse.getOpenid();
		if (openid == null) {
			OAuth2Error error = new OAuth2Error(weChatOffiaccountTokenResponse.getErrcode(),
					weChatOffiaccountTokenResponse.getErrmsg(),
					OAuth2WeChatOffiaccountEndpointUtils.AUTH_CODE2SESSION_URI);
			throw new OAuth2AuthenticationException(error);
		}

		return weChatOffiaccountTokenResponse;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param weChatOffiaccount 微信公众号配置
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount) {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(weChatOffiaccount.getSuccessUrl() + "?" + weChatOffiaccount.getParameterName() + "="
					+ accessToken.getTokenValue());
		}
		catch (IOException e) {
			throw new RedirectWeChatOffiaccountException("微信公众号重定向异常", e);
		}
	}

	/**
	 * 根据 appid 获取 微信公众号属性配置
	 * @param appid 公众号ID
	 * @return 返回 微信公众号属性配置
	 */
	@Override
	public WeChatOffiaccountProperties.WeChatOffiaccount getWeChatOffiaccountByAppid(String appid) {
		List<WeChatOffiaccountProperties.WeChatOffiaccount> list = weChatOffiaccountProperties.getList();
		if (list == null) {
			throw new AppidWeChatOffiaccountException("appid 未配置");
		}

		for (WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount : list) {
			if (appid.equals(weChatOffiaccount.getAppid())) {
				return weChatOffiaccount;
			}
		}

		throw new AppidWeChatOffiaccountException("未匹配到 appid");
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 公众号ID
	 * @return 返回重定向的地址
	 */
	@Override
	public String getRedirectUriByAppid(String appid) {
		WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount = getWeChatOffiaccountByAppid(appid);
		String redirectUriPrefix = weChatOffiaccount.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid, StandardCharsets.UTF_8);
		}
		else {
			throw new RedirectUriWeChatOffiaccountException("重定向地址前缀不能为空");
		}
	}

	/**
	 * 根据 AppID(公众号ID) 查询 AppSecret(公众号密钥)
	 * @param appid AppID(公众号ID)，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 * @return 返回 AppSecret(公众号密钥)，<a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount = getWeChatOffiaccountByAppid(appid);
		return weChatOffiaccount.getSecret();
	}

}
