package org.springframework.security.oauth2.server.authorization.http;

/*-
 * #%L
 * spring-boot-starter-wechat-offiaccount
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2WeChatOffiaccountAuthenticationToken.WECHAT_OFFIACCOUNT;

/**
 * 微信公众号授权码接收服务
 *
 * @see <a href=
 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">网页授权</a>
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AccessTokenResponse
 * @see DefaultOAuth2AccessTokenResponseMapConverter
 * @see DefaultMapOAuth2AccessTokenResponseConverter
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class WeChatOffiaccountCodeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-offiaccount/code";

	public static final String TOKEN_URL = "/oauth2/token?grant_type={grant_type}&appid={appid}&code={code}&state={state}&client_id={client_id}&client_secret={client_secret}&remote_address={remote_address}&session_id={session_id}";

	/**
	 * 微信公众号使用code获取授权凭证URL前缀
	 */
	private String prefixUrl = PREFIX_URL;

	private WeChatOffiaccountProperties weChatOffiaccountProperties;

	private WeChatOffiaccountService weChatOffiaccountService;

	@Autowired
	public void setWeChatOffiaccountProperties(WeChatOffiaccountProperties weChatOffiaccountProperties) {
		this.weChatOffiaccountProperties = weChatOffiaccountProperties;
	}

	@Autowired
	public void setWeChatOffiaccountService(WeChatOffiaccountService weChatOffiaccountService) {
		this.weChatOffiaccountService = weChatOffiaccountService;
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
			String code = request.getParameter(OAuth2ParameterNames.CODE);
			String state = request.getParameter(OAuth2ParameterNames.STATE);
			String grantType = WECHAT_OFFIACCOUNT.getValue();

			WeChatOffiaccountProperties.WeChatOffiaccount offiaccount = weChatOffiaccountService
					.getWeChatOffiaccountByAppid(appid);
			String clientId = offiaccount.getClientId();
			String clientSecret = offiaccount.getClientSecret();
			String tokenUrlPrefix = offiaccount.getTokenUrlPrefix();
			String scope = offiaccount.getScope();

			String remoteHost = request.getRemoteHost();
			HttpSession session = request.getSession(false);

			Map<String, String> uriVariables = new HashMap<>(8);
			uriVariables.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
			uriVariables.put(OAuth2WeChatOffiaccountParameterNames.APPID, appid);
			uriVariables.put(OAuth2ParameterNames.CODE, code);
			uriVariables.put(OAuth2ParameterNames.STATE, state);
			uriVariables.put(OAuth2ParameterNames.SCOPE, scope);
			uriVariables.put(OAuth2ParameterNames.CLIENT_ID, clientId);
			uriVariables.put(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
			uriVariables.put(OAuth2WeChatOffiaccountParameterNames.REMOTE_ADDRESS, remoteHost);
			uriVariables.put(OAuth2WeChatOffiaccountParameterNames.SESSION_ID, session == null ? "" : session.getId());

			OAuth2AccessTokenResponse oauth2AccessTokenResponse = weChatOffiaccountService
					.getOAuth2AccessTokenResponse(request, response, tokenUrlPrefix, TOKEN_URL, uriVariables);
			if (oauth2AccessTokenResponse == null) {
				return;
			}

			weChatOffiaccountService.sendRedirect(request, response, uriVariables, oauth2AccessTokenResponse,
					offiaccount);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
