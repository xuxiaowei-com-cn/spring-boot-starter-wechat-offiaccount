package org.springframework.security.oauth2.server.authorization.exception;

import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 微信公众号 Secret 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class SecretWeChatOffiaccountException extends WeChatOffiaccountException {

	public SecretWeChatOffiaccountException(String errorCode) {
		super(errorCode);
	}

	public SecretWeChatOffiaccountException(OAuth2Error error) {
		super(error);
	}

	public SecretWeChatOffiaccountException(OAuth2Error error, Throwable cause) {
		super(error, cause);
	}

	public SecretWeChatOffiaccountException(OAuth2Error error, String message) {
		super(error, message);
	}

	public SecretWeChatOffiaccountException(OAuth2Error error, String message, Throwable cause) {
		super(error, message, cause);
	}

	@Override
	public OAuth2Error getError() {
		return super.getError();
	}

}
