package org.springframework.security.oauth2.server.authorization.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 微信公众号属性配置类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties("wechat.offiaccount")
public class WeChatOffiaccountProperties {

	/**
	 * 微信公众号属性配置列表
	 */
	private List<WeChatOffiaccount> list;

	/**
	 * 默认微信公众号的权限
	 */
	private String defaultRole;

	/**
	 * 微信公众号属性配置类
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Data
	public static class WeChatOffiaccount {

		/**
		 * AppID(公众号ID)
		 */
		private String appid;

		/**
		 * AppSecret(公众号密钥)
		 */
		private String secret;

		/**
		 * 重定向的网址前缀（程序使用时，会在后面拼接 /{@link #appid}）
		 */
		private String redirectUriPrefix;

		/**
		 * OAuth2 客户ID
		 */
		private String clientId;

		/**
		 * OAuth2 客户秘钥
		 */
		private String clientSecret;

		/**
		 * 获取 Token URL 前缀
		 */
		private String tokenUrlPrefix;

		/**
		 * 授权范围
		 */
		private String scope;

	}

}
