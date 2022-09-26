package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Map;

/**
 * 微信公众号 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
public interface WeChatOffiaccountService {

	/**
	 * 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID(公众号ID)
	 * @param code
	 * @param openid - code2Session</a>
	 * @param credentials 证书
	 * @param unionid 机制说明</a>。
	 * @param accessToken
	 * @param refreshToken
	 * @param expiresIn
	 * @param scope
	 * @return 返回 认证信息
	 */
	AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String openid,
			Object credentials, String unionid, String accessToken, String refreshToken, Integer expiresIn,
			String scope);

	/**
	 * 根据 AppID(公众号ID)、code、jsCode2SessionUrl 获取Token
	 * @param appid AppID(公众号ID)
	 * @param code
	 * @param accessTokenUrl
	 */
	WeChatOffiaccountTokenResponse getAccessTokenResponse(String appid, String code, String accessTokenUrl);

}
