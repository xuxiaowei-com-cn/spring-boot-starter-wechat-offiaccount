package org.springframework.security.oauth2.server.authorization.exception;

/**
 * 重定向 异常
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class RedirectWeChatOffiaccountException extends WeChatOffiaccountException {

	public RedirectWeChatOffiaccountException(String message) {
		super(message);
	}

	public RedirectWeChatOffiaccountException(String message, Throwable cause) {
		super(message, cause);
	}

}
