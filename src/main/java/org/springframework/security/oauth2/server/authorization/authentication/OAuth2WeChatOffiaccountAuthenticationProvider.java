package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountTokenResponse;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2WeChatOffiaccountConfigurerUtils;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

/**
 * 微信公众号 OAuth2 身份验证提供程序
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see AnonymousAuthenticationProvider
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientSecretAuthenticationProvider
 * @see PublicClientAuthenticationProvider
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2RefreshTokenAuthenticationProvider
 * @see OAuth2ClientCredentialsAuthenticationProvider
 * @see OAuth2TokenIntrospectionAuthenticationProvider
 * @see OAuth2TokenRevocationAuthenticationProvider
 * @see OidcUserInfoAuthenticationProvider
 */
public class OAuth2WeChatOffiaccountAuthenticationProvider implements AuthenticationProvider {

	/**
	 * @see OAuth2TokenContext#getAuthorizedScopes()
	 */
	private static final String AUTHORIZED_SCOPE_KEY = OAuth2Authorization.class.getName().concat(".AUTHORIZED_SCOPE");

	/**
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">第二步：通过
	 * code 换取网页授权access_token</a>
	 */
	public static final String ACCESS_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={appid}&secret={secret}&code={code}&grant_type=authorization_code";

	private final HttpSecurity builder;

	@Setter
	private OAuth2AuthorizationService authorizationService;

	@Setter
	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	@Setter
	private WeChatOffiaccountService wechatOffiaccountService;

	public OAuth2WeChatOffiaccountAuthenticationProvider(HttpSecurity builder) {
		Assert.notNull(builder, "HttpSecurityBuilder<?> 不能为空");
		this.builder = builder;
		builder.authenticationProvider(this);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		// 初始化变量默认值
		variableDefaults();

		OAuth2WeChatOffiaccountAuthenticationToken grantAuthenticationToken = (OAuth2WeChatOffiaccountAuthenticationToken) authentication;

		String appid = grantAuthenticationToken.getAppid();
		String code = grantAuthenticationToken.getCode();
		Map<String, Object> additionalParameters = grantAuthenticationToken.getAdditionalParameters();
		Set<String> requestedScopes = StringUtils.commaDelimitedListToSet(grantAuthenticationToken.getScope());

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
				.getAuthenticatedClientElseThrowInvalidClient(grantAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (registeredClient == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "注册客户不能为空", null);
			throw new OAuth2AuthenticationException(error);
		}

		Set<String> allowedScopes = registeredClient.getScopes();

		if (requestedScopes.isEmpty()) {
			// 请求中的 scope 为空，允许全部
			requestedScopes = allowedScopes;
		}
		else if (!allowedScopes.containsAll(requestedScopes)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
					"OAuth 2.0 参数: " + OAuth2ParameterNames.SCOPE, null);
			throw new OAuth2AuthenticationException(error);
		}

		WeChatOffiaccountTokenResponse weChatOffiaccountTokenResponse = wechatOffiaccountService
				.getAccessTokenResponse(appid, code, ACCESS_TOKEN_URL);

		String openid = weChatOffiaccountTokenResponse.getOpenid();
		String unionid = weChatOffiaccountTokenResponse.getUnionid();

		String accessToken = weChatOffiaccountTokenResponse.getAccessToken();
		String refreshToken = weChatOffiaccountTokenResponse.getRefreshToken();
		Integer expiresIn = weChatOffiaccountTokenResponse.getExpiresIn();
		String scope = weChatOffiaccountTokenResponse.getScope();

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
		builder.principalName(openid);
		builder.authorizationGrantType(OAuth2WeChatOffiaccountAuthenticationToken.WECHAT_OFFIACCOUNT);

		AbstractAuthenticationToken abstractAuthenticationToken = wechatOffiaccountService.authenticationToken(
				clientPrincipal, additionalParameters, grantAuthenticationToken.getDetails(), appid, code, openid, null,
				unionid, accessToken, refreshToken, expiresIn, scope);

		builder.attribute(Principal.class.getName(), abstractAuthenticationToken);
		builder.attribute(AUTHORIZED_SCOPE_KEY, requestedScopes);

		OAuth2Authorization authorization = builder.build();

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAttribute(AUTHORIZED_SCOPE_KEY))
				.authorizationGrantType(OAuth2WeChatOffiaccountAuthenticationToken.WECHAT_OFFIACCOUNT)
				.authorizationGrant(grantAuthenticationToken);
		// @formatter:on

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", null);
			throw new OAuth2AuthenticationException(error);
		}
		OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(oauth2AccessToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
							((ClaimAccessor) generatedAccessToken).getClaims()));
		}
		else {
			authorizationBuilder.accessToken(oauth2AccessToken);
		}

		// ----- Refresh token -----
		OAuth2RefreshToken oauth2RefreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
		// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "令牌生成器无法生成刷新令牌。", null);
				throw new OAuth2AuthenticationException(error);
			}
			oauth2RefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(oauth2RefreshToken);
		}

		authorization = authorizationBuilder.build();

		authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, oauth2AccessToken,
				oauth2RefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2WeChatOffiaccountAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * 初始化变量默认值
	 */
	private void variableDefaults() {
		if (authorizationService == null) {
			authorizationService = OAuth2WeChatOffiaccountConfigurerUtils.getAuthorizationService(builder);
		}

		if (tokenGenerator == null) {
			tokenGenerator = OAuth2WeChatOffiaccountConfigurerUtils.getTokenGenerator(builder);
		}

		if (wechatOffiaccountService == null) {
			wechatOffiaccountService = OAuth2WeChatOffiaccountConfigurerUtils.getWeChatOffiaccountService(builder);
		}
	}

}
