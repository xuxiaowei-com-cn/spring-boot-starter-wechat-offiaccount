package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.InMemoryWeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.client.WeChatOffiaccountService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatOffiaccountProperties;

import java.util.List;

/**
 * 微信公众号 配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration
public class OAuth2WeChatOffiaccountConfiguration {

	private WeChatOffiaccountProperties weChatOffiaccountProperties;

	@Autowired
	public void setWeChatOffiaccountProperties(WeChatOffiaccountProperties weChatOffiaccountProperties) {
		this.weChatOffiaccountProperties = weChatOffiaccountProperties;
	}

	@Bean
	@ConditionalOnMissingBean
	public WeChatOffiaccountService weChatOffiaccountService() {
		List<WeChatOffiaccountProperties.WeChatOffiaccount> weChatOffiaccountPropertiesList = weChatOffiaccountProperties
				.getList();
		String defaultRole = weChatOffiaccountProperties.getDefaultRole();
		return new InMemoryWeChatOffiaccountService(weChatOffiaccountPropertiesList, defaultRole);
	}

}
