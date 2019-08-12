package datatx.geode.security;

import org.apache.commons.lang.StringUtils;
import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import datatx.geode.security.Encryption.EncryptionException;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

public class LdapUserSecurityManager implements SecurityManager {
	public static final String LDAP_SERVER_NAME = "security-ldap-server";
	public static final String LDAP_BASEDN_NAME = "security-ldap-basedn";
	public static final String LDAP_SSL_NAME = "security-ldap-usessl";
	public static final String LDAP_SEARCH_GROUP = "security-ldapSearchGroup";
	public static final String LDAP_GEMFIRE_AUTHZ_QUERY = "security-ldapGemfireAuthorizationQuery";
	public static final String LDAP_GROUP_TEMPLATE = "security-ldap-group-template";
	public static final String LDAP_GROUP_SEPERATOR = "security-ldap-group-separator";
	public static final String ENCRYPTED = "ENCRYPTED";
	public static final String LDAP_CREDENTIAL_REFRESH_TIME = "security-credentials-refresh";
	public static final String UAA_URL = "security-uaa-url";
	public static final String UAA_ENTITY = "security-uaa-entity";
	public static final String CREDHUB_URL = "security-credhub-url";
	public static final String ENABLE_UAA_CREDHUB = "security-enable-uaa-credhub";
	public static final String ENCRYPTION_KEY = "security-encryption-master";
	public static final String SECURITY_PEER = "security-peer";
	public static final String FILE = "file:";

	private static final String APPLID = "APPLID";
	private static final String ENV = "ENV";
	private static final String RESOURCE = "RESOURCE";
	private static final String PERMISSIONS = "PERMISSIONS";
	private static final String REGION = "REGION";
	private static final String CLUSTER = "CLUSTER";
	private static final String DATA = "DATA";

	private NamingEnumeration<?> authorities;

	private long ldapRefreshTime = 0;

	private Map<String, User> userAuthorities = new HashMap<String, User>();

	private String ldapUrlScheme = "ldap://";
	private String ldapServer = "";
	private String basedn;
	private String searchGroup;
	private String ldapQuery;
	private String uaaUrl;
	private String uaaEntity;
	private String credhubUrl;
	private String ldapSeperator;
	private String encryptionKey;

	private boolean enableUaaCredhub = false;
	private boolean peer;

	private HashMap<String, Integer> templateMap;

	private Logger LOG = LoggerFactory.getLogger(LdapUserSecurityManager.class);

	void setUserAuthorities(Map<String, User> userAuthorities) {
		this.userAuthorities = userAuthorities;
	}

	public void init(final Properties securityProperties) throws AuthenticationFailedException {
		String str;
		LOG.info("LdapUserSecurityManager processing properties");

		if (securityProperties.getProperty(ENABLE_UAA_CREDHUB) != null) {
			enableUaaCredhub = Boolean.valueOf(securityProperties.getProperty(ENABLE_UAA_CREDHUB));
		}

		ldapServer = securityProperties.getProperty(LDAP_SERVER_NAME);
		if (this.ldapServer == null || this.ldapServer.length() == 0) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP server property [" + LDAP_SERVER_NAME + "] not specified");
		}

		basedn = securityProperties.getProperty(LDAP_BASEDN_NAME);
		if (this.basedn == null || this.basedn.length() == 0) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP base DN property [" + LDAP_BASEDN_NAME + "] not specified");
		}

		searchGroup = securityProperties.getProperty(LDAP_SEARCH_GROUP);
		if (searchGroup == null) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP server property [" + LDAP_SEARCH_GROUP + "] not specified");
		}

		ldapQuery = securityProperties.getProperty(LDAP_GEMFIRE_AUTHZ_QUERY);
		if (ldapQuery == null) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP server property [" + LDAP_GEMFIRE_AUTHZ_QUERY + "] not specified");
		}

		String refreshTime = securityProperties.getProperty(LDAP_CREDENTIAL_REFRESH_TIME);
		if (StringUtils.isNotEmpty(refreshTime) && StringUtils.isNumeric(refreshTime)) {
			ldapRefreshTime = (Long.parseLong(refreshTime) * 60) * 1000;
		} else {
			ldapRefreshTime = (30 * 60) * 1000;
		}

		str = securityProperties.getProperty(LDAP_SSL_NAME);
		if (str != null && str.toLowerCase().equals("true")) {
			ldapUrlScheme = "ldaps://";
		} else {
			ldapUrlScheme = "ldap://";
		}

		if (enableUaaCredhub) {
			uaaUrl = securityProperties.getProperty(UAA_URL);
			if (uaaUrl == null || uaaUrl.length() == 0) {
				throw new AuthenticationFailedException(
						"LdapUserAuthenticator: UAA URL property [" + UAA_URL + "] not specified");
			}
		}

		if (enableUaaCredhub) {
			uaaEntity = securityProperties.getProperty(UAA_ENTITY);
			if (uaaEntity == null || uaaEntity.length() == 0) {
				throw new AuthenticationFailedException(
						"LdapUserAuthenticator: UAA Entity property [" + UAA_ENTITY + "] not specified");
			}
		}

		if (enableUaaCredhub) {
			credhubUrl = securityProperties.getProperty(CREDHUB_URL);
			if (credhubUrl == null || credhubUrl.length() == 0) {
				throw new AuthenticationFailedException(
						"LdapUserAuthenticator: Credhub URL property [" + CREDHUB_URL + "] not specified");
			}
		}

		ldapSeperator = securityProperties.getProperty(LDAP_GROUP_SEPERATOR);
		if (ldapSeperator == null || ldapSeperator.length() == 0) {
			throw new AuthenticationFailedException("LdapUserAuthenticator: LDAP Group Seperator property ["
					+ LDAP_GROUP_SEPERATOR + "] not specified");
		}

		str = securityProperties.getProperty(SECURITY_PEER);
		if (str != null && str.length() > 0) {
			peer = Boolean.valueOf(str);
		}

		encryptionKey = getKey(securityProperties.getProperty(ENCRYPTION_KEY));

		String template = securityProperties.getProperty(LDAP_GROUP_TEMPLATE);
		if (template == null || template.length() == 0) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP Group Template property [" + LDAP_GROUP_TEMPLATE + "] not specified");
		}
		parseTemplate(template);
	}

	private String getKey(String key) throws AuthenticationFailedException {
		if (key != null && key.length() > 0) {
			if (key.toLowerCase().startsWith(FILE)) {
				StringBuilder sb = new StringBuilder();
				try {
					BufferedReader br = Files.newBufferedReader(Paths.get(key.substring(FILE.length(), key.length())));
					String line;
					while ((line = br.readLine()) != null) {
						sb.append(line);
					}
					return sb.toString();
				} catch (IOException e) {
					throw new AuthenticationFailedException("Failed to get encryption master key from " + key);
				}
			} else {
				return key;
			}
		} else {
			LOG.warn("No encryption master key found.");
		}
		return null;
	}

	private void parseTemplate(String template) {
		templateMap = new HashMap<String, Integer>();
		String[] templateComponents = template.split(ldapSeperator);
		if (templateComponents != null && templateComponents.length > 0) {
			for (int i = 0; i < templateComponents.length; i++) {
				if (templateComponents[i].equals(APPLID) || templateComponents[i].equals(ENV)
						|| templateComponents[i].equals(RESOURCE) || templateComponents[i].equals(PERMISSIONS)
						|| templateComponents[i].equals(REGION)) {
					templateMap.put(templateComponents[i], i + 1);
				}
			}
			if (templateMap.get(RESOURCE) == null || templateMap.get(PERMISSIONS) == null) {
				throw new AuthenticationFailedException(
						"LdapUserAuthenticator: LDAP Group Template property has an invalid format. "
								+ "Format must have RESOURCE and PERMISSIONS defined");
			}
		} else {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: LDAP Group Template property has an invalid format");
		}
	}

	private String getUAAToken() {
		String token = null;
		LOG.info("Getting UAA Token");
		CloseableHttpClient httpclient = null;
		try {
			if (this.uaaUrl.startsWith("https")) {
				httpclient = HttpClients.custom().setSSLSocketFactory(setupSSL()).build();
			} else {
				httpclient = HttpClients.createDefault();
			}

			HttpUriRequest postRequest = RequestBuilder.post().setUri(this.uaaUrl)
					.addHeader("Content-Type", "application/x-www-form-urlencoded")
					.setEntity(new StringEntity(this.uaaEntity)).build();

			HttpResponse response = null;
			try {
				response = httpclient.execute(postRequest);
				int code = response.getStatusLine().getStatusCode();
				LOG.info("HTTP UAA response code: " + code);
				if (code == 200) {
					HttpEntity responseEntity = response.getEntity();
					if (responseEntity != null) {
						try {
							InputStream instream = responseEntity.getContent();
							byte[] responseData = new byte[5000];
							int bytesRead = instream.read(responseData);
							if (bytesRead > 0) {
								String str = new String(responseData).trim();
								if (!str.startsWith("{"))
									str = "{" + str;
								if (!str.endsWith("}"))
									str = str + "}";
								JSONObject json = new JSONObject(str);
								token = json.getString("access_token");
								LOG.info("UAA Post Response: " + str);
							} else {
								LOG.info("No UAA Post Response received");
							}
							instream.close();
						} catch (Exception e) {
							LOG.error("Error reading UAA HTTP response exception: " + e.getMessage());
						}
					} else {
						LOG.warn("HTTP UAA Post response entity was null");
					}
				} else {
					LOG.error("Invalid response code received from HTTP UAA Post code = " + code);
				}
			} catch (Exception e) {
				LOG.error("Error executing HTTP UAA post exception: " + e.getMessage());
			}
		} catch (Exception e) {
			LOG.error("Error adding UAA header/entity exception: " + e.getMessage());
		}
		if (httpclient != null) {
			try {
				httpclient.close();
			} catch (IOException e) {
				LOG.error("Error closing UAA HTTP Client exception: " + e.getMessage());
			}
		}

		return token;
	}

	private String getCredhubCredentials(String user, String token) {
		String password = null;
		LOG.info("Getting Credhub Credentials");
		CloseableHttpClient httpclient = null;
		try {
			if (this.credhubUrl.startsWith("https")) {
				httpclient = HttpClients.custom().setSSLSocketFactory(setupSSL()).build();
			} else {
				httpclient = HttpClients.createDefault();
			}

			URIBuilder builder = new URIBuilder(this.credhubUrl);
			builder.setParameter("name", user);
			HttpGet httpGet = new HttpGet(builder.build());
			httpGet.addHeader("content-type", "application/json");
			httpGet.addHeader("authorization", "bearer " + token);
			HttpResponse response = null;
			try {
				response = httpclient.execute(httpGet);
				int code = response.getStatusLine().getStatusCode();
				LOG.info("HTTP credhub response code: " + code);
				if (code == 200) {
					HttpEntity entity = response.getEntity();
					if (entity != null) {
						try {
							InputStream instream = entity.getContent();
							byte[] responseData = new byte[5000];
							int bytesRead = instream.read(responseData);
							if (bytesRead > 0) {
								String str = new String(responseData).trim();
								if (!str.startsWith("{"))
									str = "{" + str;
								if (!str.endsWith("}"))
									str = str + "}";
								JSONObject json = new JSONObject(str);
								JSONArray arr = json.getJSONArray("data");
								int length = json.length();
								for (int i = 0; i < length; i++) {
									JSONObject jObj = arr.getJSONObject(i);
									jObj = jObj.getJSONObject("value");
									password = (String) jObj.get("password");
								}
								LOG.info("Credhub HTTP Get Response: " + str);
							} else {
								LOG.info("Credhub HTTP no response to Get received");
							}
							instream.close();
						} catch (Exception e) {
							LOG.error("Error reading HTTP Credhub Get response exception: " + e.getMessage());
						}
					} else {
						LOG.warn("HTTP Credhub Get response entity was null");
					}
				} else {
					LOG.error("Invalid response code received from HTTP Credhub Get code = " + code);
				}
			} catch (Exception e) {
				LOG.error("Error executing HTTP Credhub Get exception: " + e.getMessage());
			}
		} catch (Exception e) {
			LOG.error("Error adding Credhub header/entity exception: " + e.getMessage());
		}

		if (httpclient != null) {
			try {
				httpclient.close();
			} catch (IOException e) {
				LOG.error("Error closing Credhub HTTP Client exception: " + e.getMessage());
			}
		}

		return password;
	}

	public Principal authenticate(final Properties credentials) throws AuthenticationFailedException {
		String token;
		String passwd = null;

		String userName = credentials.getProperty(UserPasswordAuthInit.USER_NAME);
		if (userName == null) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: user name property [" + UserPasswordAuthInit.USER_NAME + "] not provided");
		}

		if (userName.toUpperCase().equals("PEER") && peer) {
			return new UsernamePrincipal(SECURITY_PEER);
		}

		if (!enableUaaCredhub) {
			passwd = credentials.getProperty(UserPasswordAuthInit.PASSWORD);
			if (passwd == null) {
				throw new AuthenticationFailedException("LdapUserAuthenticator: password name property ["
						+ UserPasswordAuthInit.PASSWORD + "] not provided");
			}
		}

		Optional<UsernamePrincipal> userNamePrincipalOpt = checkUserNeedsToBeRefreshed(userName);

		if (userNamePrincipalOpt.isPresent()) {
			return userNamePrincipalOpt.get();
		}

		if (enableUaaCredhub) {
			token = getUAAToken();
			if (token == null) {
				throw new AuthenticationFailedException("Unable to retreive token from UAA server");
			} else {
				passwd = getCredhubCredentials(userName, token);
			}
		}

		Properties env = new Properties();

		if (passwd == null || passwd.length() == 0) {
			throw new AuthenticationFailedException("LdapUserAuthenticator: Failure with provided username, password "
					+ "combination for user name: " + userName);
		}

		if (passwd.startsWith(ENCRYPTED)) {
			if (encryptionKey != null) {
				try {
					passwd = passwd.substring(ENCRYPTED.length());
					env.put(Context.SECURITY_CREDENTIALS, Encryption.decrypt(passwd, encryptionKey.getBytes()));
				} catch (EncryptionException ce) {
					throw new AuthenticationFailedException(ce.getMessage());
				}
			} else {
				throw new AuthenticationFailedException(
						"LdapUserAuthenticator: encrypted password but no master key provided");
			}
		} else {
			env.put(Context.SECURITY_CREDENTIALS, passwd);
		}

		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

		env.put(Context.PROVIDER_URL, this.ldapUrlScheme + this.ldapServer);
		String fullentry = "cn=" + userName + "," + this.basedn;
		env.put(Context.SECURITY_PRINCIPAL, fullentry);

		try {
			DirContext ctx = new InitialDirContext(env);
			authorities = ctx.search(searchGroup, ldapQuery, new Object[] { userName }, null);
			ctx.close();

			List<ResourcePermission> allOfUsersPermissions = new ArrayList<ResourcePermission>();
			while (authorities.hasMoreElements()) {
				SearchResult nextSearchResult = ((SearchResult) authorities.nextElement());
				List<ResourcePermission> resourcePermissions = readPermission(nextSearchResult.getName());
				if (resourcePermissions != null && resourcePermissions.size() > 0)
					allOfUsersPermissions.addAll(resourcePermissions);
			}

			if (null == userAuthorities.get(userName)) {
				User user = User.newBuilder().withName(userName)
						.withLastTimeAuthenticatedWithLDAP(System.currentTimeMillis()).withRoles(allOfUsersPermissions)
						.build();
				userAuthorities.put(userName, user);
			} else {
				userAuthorities.get(userName).setLastTimeAuthenticatedWithLDAP(System.currentTimeMillis());
				userAuthorities.get(userName).setRoles(allOfUsersPermissions);
			}

		} catch (Exception e) {
			throw new AuthenticationFailedException(
					"LdapUserAuthenticator: Failure with provided username, password " + "combination for user name: "
							+ userName + "\n Original exception message was: " + e.getMessage());
		}
		return new UsernamePrincipal(userName);
	}

	Optional<UsernamePrincipal> checkUserNeedsToBeRefreshed(String userName) {
		User currentUser = userAuthorities.get(userName);
		if (currentUser != null) {
			if (((System.currentTimeMillis() + ldapRefreshTime) - currentUser.getLastTimeAuthenticatedWithLDAP()) > 0) {
				return Optional.of(new UsernamePrincipal(userName));
			}
		}
		return Optional.empty();
	}

	public boolean authorize(final Object principal, final ResourcePermission context) {
		if (principal == null)
			return false;

		if (principal.toString().equals(SECURITY_PEER)) {
			return true;
		}

		User user = this.userAuthorities.get(principal.toString());
		if (user == null)
			return false;

		for (ResourcePermission resourcePermission : this.userAuthorities.get(user.name).roles) {
			if (resourcePermission == null)
				continue;

			if (resourcePermission.implies(context)) {
				return true;
			}
		}
		return false;
	}

	protected List<ResourcePermission> readPermission(String authorityString) {
		String ldapRoles = authorityString.split(",")[0].replace("cn=", "");
		String[] ldapRole = ldapRoles.split(ldapSeperator);

		if (isValidLdapRole(ldapRole)) {
			return createResourcePermissions(ldapRole);
		}

		return null;
	}

	private boolean isValidLdapRole(String[] ldapRoles) {
		int index;
		if (templateMap.get(RESOURCE) != null) {
			index = templateMap.get(RESOURCE);
			if (!ldapRoles[index - 1].equalsIgnoreCase(CLUSTER) && !ldapRoles[index - 1].equalsIgnoreCase(DATA))
				return false;
			index = templateMap.get(PERMISSIONS);
			String permissions = ldapRoles[index - 1];
			for (int i = 0; i < permissions.length(); i++) {
				switch (permissions.charAt(i)) {
				case 'A':
				case 'M':
				case 'R':
				case 'W':
					break;
				default:
					return false;
				}
			}
		} else {
			return false;
		}
		return true;
	}

	private List<ResourcePermission> createResourcePermissions(String[] ldapRole) {
		String regionName = null;
		String resource = null;
		String operations = null;
		if (templateMap.get(RESOURCE) != null && templateMap.get(RESOURCE) - 1 < ldapRole.length)
			resource = ldapRole[templateMap.get(RESOURCE) - 1].toUpperCase();
		if (templateMap.get(PERMISSIONS) != null && templateMap.get(PERMISSIONS) - 1 < ldapRole.length)
			operations = ldapRole[templateMap.get(PERMISSIONS) - 1].toUpperCase();
		if (templateMap.get(REGION) != null && templateMap.get(REGION) - 1 < ldapRole.length)
			regionName = ldapRole[templateMap.get(REGION)];

		if (regionName == null || regionName.length() == 0) {
			regionName = "*";
		}

		if (resource == null || operations == null)
			return null;

		List<ResourcePermission> resourcePermissions = new ArrayList<ResourcePermission>();
		for (int i = 0; i < operations.length(); i++) {
			switch (operations.charAt(i)) {
			case 'A':
				resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource),
						ResourcePermission.Operation.ALL, regionName));
				break;
			case 'M':
				resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource),
						ResourcePermission.Operation.MANAGE, regionName));
				break;
			case 'R':
				resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource),
						ResourcePermission.Operation.READ, regionName));
				break;
			case 'W':
				resourcePermissions.add(new ResourcePermission(ResourcePermission.Resource.valueOf(resource),
						ResourcePermission.Operation.WRITE, regionName));
				break;
			}
		}
		return resourcePermissions;
	}

	private TrustManager[] get_trust_mgr() {
		TrustManager[] certs = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String t) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String t) {
			}
		} };
		return certs;
	}

	private SSLConnectionSocketFactory setupSSL() throws Exception {
		SSLContext ssl_ctx = SSLContext.getInstance("TLS");
		TrustManager[] trust_mgr = get_trust_mgr();
		ssl_ctx.init(null, trust_mgr, new SecureRandom());
		HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
		return new SSLConnectionSocketFactory(ssl_ctx, allowAllHosts);
	}

	public static class User {
		String name;
		String password;
		long lastTimeAuthenticatedWithLDAP = 0;

		List<ResourcePermission> roles = new ArrayList<ResourcePermission>();

		private User(Builder builder) {
			name = builder.name;
			password = builder.password;
			roles = builder.roles;
		}

		public void setLastTimeAuthenticatedWithLDAP(long lastTimeAuthenticatedWithLDAP) {
			this.lastTimeAuthenticatedWithLDAP = lastTimeAuthenticatedWithLDAP;
		}

		public void setRoles(List<ResourcePermission> permissions) {
			this.roles = permissions;
		}

		public static Builder newBuilder() {
			return new Builder();
		}

		public String getName() {
			return name;
		}

		public String getPassword() {
			return password;
		}

		public long getLastTimeAuthenticatedWithLDAP() {
			return lastTimeAuthenticatedWithLDAP;
		}

		public List<ResourcePermission> getRoles() {
			return roles;
		}

		@SuppressWarnings("unused")
		public static final class Builder {
			private String name;
			private String password;
			private long lastTimeAuthenticatedWithLDAP;

			private List<ResourcePermission> roles;

			private Builder() {
			}

			public Builder withName(String name) {
				this.name = name;
				return this;
			}

			public Builder withPassword(String password) {
				this.password = password;
				return this;
			}

			public Builder withLastTimeAuthenticatedWithLDAP(long lastTimeAuthenticatedWithLDAP) {
				this.lastTimeAuthenticatedWithLDAP = lastTimeAuthenticatedWithLDAP;
				return this;
			}

			public Builder withRoles(List<ResourcePermission> roles) {
				this.roles = roles;
				return this;
			}

			public User build() {
				return new User(this);
			}
		}
	}
}
