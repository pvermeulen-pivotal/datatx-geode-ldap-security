package datatx.geode.security;

import java.util.Properties;

import org.apache.geode.LogWriter;
import org.apache.geode.distributed.DistributedMember;
import org.apache.geode.security.AuthInitialize;
import org.apache.geode.security.AuthenticationFailedException;

public class UserPasswordAuthInit implements AuthInitialize {

	public static final String USER_NAME = "security-username";

	public static final String PASSWORD = "security-password";

	public static AuthInitialize create() {
		return new UserPasswordAuthInit();
	}

	@SuppressWarnings("deprecation")
	public void init(LogWriter systemLogger, LogWriter securityLogger) throws AuthenticationFailedException {
	}

	private UserPasswordAuthInit() {
	}

	public Properties getCredentials(Properties props, DistributedMember server, boolean isPeer)
			throws AuthenticationFailedException {

		Properties newProps = new Properties();
		String userName = props.getProperty(USER_NAME);
		if (userName == null) {
			throw new AuthenticationFailedException(
					"UserPasswordAuthInit: user name property [" + USER_NAME + "] not set.");
		}
		newProps.setProperty(USER_NAME, userName);
		String passwd = props.getProperty(PASSWORD);
		if (passwd == null) {
			passwd = "";
		}
		newProps.setProperty(PASSWORD, passwd);

		return newProps;
	}

	public void close() {
	}

}
