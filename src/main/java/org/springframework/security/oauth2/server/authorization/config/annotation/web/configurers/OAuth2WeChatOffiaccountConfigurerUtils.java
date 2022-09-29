package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryWeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 微信公众号 OAuth 2.0 配置器的实用方法。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ConfigurerUtils
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOffiaccountConfigurerUtils {

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		return OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
	}

	public static WeChatOffiaccountService getWeChatOffiaccountService(HttpSecurity httpSecurity) {
		WeChatOffiaccountService wechatOffiaccountService = httpSecurity
				.getSharedObject(WeChatOffiaccountService.class);
		if (wechatOffiaccountService == null) {
			wechatOffiaccountService = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity,
					WeChatOffiaccountService.class);
			if (wechatOffiaccountService == null) {
				WeChatOffiaccountProperties weChatOffiaccountProperties = OAuth2ConfigurerUtils
						.getOptionalBean(httpSecurity, WeChatOffiaccountProperties.class);
				wechatOffiaccountService = new InMemoryWeChatOffiaccountService(weChatOffiaccountProperties);
			}
		}
		return wechatOffiaccountService;
	}

}
