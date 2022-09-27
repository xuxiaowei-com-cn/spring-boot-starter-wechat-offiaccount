package org.springframework.security.oauth2.server.authorization.exception;

/**
 * 微信公众号父异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class WeChatOffiaccountException extends RuntimeException {

	public WeChatOffiaccountException(String message) {
		super(message);
	}

	public WeChatOffiaccountException(String message, Throwable cause) {
		super(message, cause);
	}

}
