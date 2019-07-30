package datatx.geode.security;

import java.io.Serializable;
import java.security.Principal;
import java.util.Map;

public class UsernamePrincipal implements Principal, Serializable {
	private static final long serialVersionUID = -5588007118920275400L;
	private final String userName;
	private Map<String, LdapUserSecurityManager.User> roles;
	public boolean admin = false;
	public boolean adminManage = false;

	public UsernamePrincipal(String userName, Map<String, LdapUserSecurityManager.User> roles) {
		this.userName = userName;
		this.roles = roles;
	}

	public UsernamePrincipal(String userName) {
		this.userName = userName;
	}

	private UsernamePrincipal(Builder builder) {
		userName = builder.userName;
		setRoles(builder.roles);
		setAdmin(builder.admin);
		setAdminManage(builder.adminManage);
	}

	public static Builder newBuilder() {
		return new Builder();
	}


	public Map<String, LdapUserSecurityManager.User> getRoles() {
		return roles;
	}

	public void setRoles(Map<String, LdapUserSecurityManager.User> roles) {
		this.roles = roles;
	}

	public boolean isAdmin() {
		return admin;
	}

	public void setAdmin(boolean admin) {
		this.admin = admin;
	}

	public boolean isAdminManage() {
		return adminManage;
	}

	public void setAdminManage(boolean adminManage) {
		this.adminManage = adminManage;
	}

	public String getName() {
		return this.userName;
	}

	@Override
	public String toString() {
		return this.userName;
	}

	public static final class Builder {
		private String userName;
		private Map<String, LdapUserSecurityManager.User> roles;
		private boolean admin;
		private boolean adminManage;

		private Builder() {
		}

		public Builder withUserName(String userName) {
			this.userName = userName;
			return this;
		}

		public Builder withRoles(Map<String, LdapUserSecurityManager.User> roles) {
			this.roles = roles;
			return this;
		}

		public Builder withAdmin(boolean admin) {
			this.admin = admin;
			return this;
		}

		public Builder withAdminManage(boolean adminManage) {
			this.adminManage = adminManage;
			return this;
		}

		public UsernamePrincipal build() {
			return new UsernamePrincipal(this);
		}
	}
}