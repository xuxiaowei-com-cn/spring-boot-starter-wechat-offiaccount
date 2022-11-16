package org.springframework.security.oauth2.core.endpoint;

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
 * 微信公众号 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public interface OAuth2WeChatOffiaccountParameterNames {

	/**
	 * AppID(公众号ID)
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	String APPID = "appid";

	/**
	 * AppSecret(公众号密钥)
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	String SECRET = "secret";

	/**
	 * 用户唯一标识
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	String OPENID = "openid";

	/**
	 * @see <a href=
	 * "https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html">微信网页开发
	 * /网页授权</a>
	 */
	String UNIONID = "unionid";

	/**
	 * 远程地址
	 */
	String REMOTE_ADDRESS = "remote_address";

	/**
	 * Session ID
	 */
	String SESSION_ID = "session_id";

}
