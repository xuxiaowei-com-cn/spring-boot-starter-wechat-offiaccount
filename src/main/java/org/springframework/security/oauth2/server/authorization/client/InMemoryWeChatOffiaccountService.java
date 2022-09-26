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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatOffiaccountParameterNames;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatOffiaccountEndpointUtils;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

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

	private final List<WeChatOffiaccountProperties.WeChatOffiaccount> weChatOffiaccountList;

	/**
	 * 默认微信公众号的权限
	 * <p>
	 * 若要自定义用户的权限，请开发者自己实现 {@link WeChatOffiaccountService}
	 */
	private final String defaultRole;

	public InMemoryWeChatOffiaccountService(List<WeChatOffiaccountProperties.WeChatOffiaccount> weChatOffiaccountList,
			String defaultRole) {
		this.weChatOffiaccountList = weChatOffiaccountList;
		this.defaultRole = defaultRole;
	}

	/**
	 * 认证信息
	 * @param appid AppID(公众号ID)
	 * @param openid
	 * @param unionid
	 * @param accessToken
	 * @param refreshToken
	 * @param expiresIn
	 * @param scope
	 * @param details 登录信息
	 * @return 返回 认证信息
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(defaultRole);
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
	 * @param appid AppID(公众号ID)
	 * @param code
	 * @param accessTokenUrl
	 * @return 返回 - code2Session</a>
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
	 * 根据 AppID(公众号ID) 查询 AppSecret(公众号密钥)
	 * @param appid AppID(公众号ID)
	 * @return 返回 AppSecret(公众号密钥)
	 */
	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		for (WeChatOffiaccountProperties.WeChatOffiaccount weChatOffiaccount : weChatOffiaccountList) {
			if (appid.equals(weChatOffiaccount.getAppid())) {
				return weChatOffiaccount.getSecret();
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2WeChatOffiaccountEndpointUtils.INVALID_ERROR_CODE, "未找到 secret",
				OAuth2WeChatOffiaccountEndpointUtils.AUTH_CODE2SESSION_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
