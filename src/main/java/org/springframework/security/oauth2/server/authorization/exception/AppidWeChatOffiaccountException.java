package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 微信公众号 AppID(公众号ID) 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class AppidWeChatOffiaccountException extends WeChatOffiaccountException {

	public AppidWeChatOffiaccountException(String errorCode) {
		super(errorCode);
	}

	public AppidWeChatOffiaccountException(OAuth2Error error) {
		super(error);
	}

	public AppidWeChatOffiaccountException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public AppidWeChatOffiaccountException(OAuth2Error error, String message) {
		super(error, message);
	}

	public AppidWeChatOffiaccountException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
