package org.springframework.security.oauth2.core.endpoint;

/**
 * 微信公众号 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
public interface OAuth2WeChatOffiaccountParameterNames {

	/**
	 * AppID(公众号ID)
	 */
	String APPID = "appid";

	/**
	 * AppSecret(公众号密钥)
	 */
	String SECRET = "secret";

	/**
	 *
	 *
	 * @see OAuth2ParameterNames#CODE
	 */
	String CODE = "code";

	/**
	 * 用户唯一标识
	 *
	 */
	String OPENID = "openid";

	/**
	
	 */
	String UNIONID = "unionid";

}
