package org.springframework.security.oauth2.server.authorization.web.authentication;

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

/**
 * 微信公众号 OAuth 2.0 协议端点的实用方法
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class OAuth2WeChatOffiaccountEndpointUtils {

	/**
	 * 微信网页开发 /网页授权
	 */
	public static final String AUTH_CODE2SESSION_URI = "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html";

	/**
	 * 错误代码
	 */
	public static final String ERROR_CODE = "C10000";

	/**
	 * 无效错误代码
	 */
	public static final String INVALID_ERROR_CODE = "C20000";

}
