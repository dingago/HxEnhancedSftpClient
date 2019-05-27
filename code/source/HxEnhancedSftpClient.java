

// -----( IS Java Code Template v1.2
// -----( CREATED: 2019-05-27 16:44:41 MDT
// -----( ON-HOST: 192.168.241.245

import com.wm.data.*;
import com.wm.util.Values;
import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
// --- <<IS-START-IMPORTS>> ---
import com.wm.app.b2b.server.Resources;
import com.wm.app.b2b.server.Server;
import com.wm.passman.PasswordManager;
import com.wm.passman.PasswordManagerException;
import com.wm.resources.WmPublicMsgBundle;
import com.wm.security.OutboundPasswordStore;
import com.wm.util.ValidationException;
import com.wm.util.i18n.MessageFormatter;
import com.wm.util.security.WmSecureString;
import com.softwareag.util.IDataMap;
import com.wm.app.b2b.server.sftp.client.*;
import com.jcraft.jsch.*;
import java.io.File;
import java.lang.reflect.Field;
import java.util.Properties;
import java.util.ResourceBundle;
// --- <<IS-END-IMPORTS>> ---

public final class HxEnhancedSftpClient

{
	// ---( internal utility methods )---

	final static HxEnhancedSftpClient _instance = new HxEnhancedSftpClient();

	static HxEnhancedSftpClient _newInstance() { return new HxEnhancedSftpClient(); }

	static HxEnhancedSftpClient _cast(Object o) { return (HxEnhancedSftpClient)o; }

	// ---( server methods )---




	public static final void login (IData pipeline)
        throws ServiceException
	{
		// --- <<IS-START(login)>> ---
		// @sigtype java 3.5
		// [i] field:0:required userAlias
		// [i] field:0:optional reuseSession {"false","true"}
		// [o] field:0:required sessionKey
		// [o] field:0:required returnCode
		// [o] field:0:required returnMsg
		IDataMap pipelineMap = new IDataMap(pipeline);
		String userAlias = pipelineMap.getAsString("userAlias");
		String reuseSession = pipelineMap.getAsString("reuseSession");
		String sessionKey = null;
		boolean bReuseSession = reuseSession == null ? false : reuseSession.equalsIgnoreCase("true");
		
		if (bReuseSession){
			//Retrieve cached session key
			sessionKey = sftpSessionManager.getSessionForAlias(userAlias);
		}
		
		if (sessionKey == null){
			try {
				//Retrieve User Alias and Server Alias
				SFTPUserAlias sftpUserAlias = retrieveUserAlias(userAlias);
				SFTPServerAlias sftpServerAlias = retrieveServerAlias(sftpUserAlias.getSftpServerAlias());
				
				//Configure JSch Session
				JSch jsch = new JSch();
				jsch.setHostKeyRepository(getHostKeyRepository());
				System.out.println(getPrivateKeyFile(sftpUserAlias.getKeyFileLocation()));
				System.out.println(retrivePasswordAsString("wm.is.admin.sftpclient.pass.phrase." + userAlias));
				jsch.addIdentity(getPrivateKeyFile(sftpUserAlias.getKeyFileLocation()), retrivePasswordAsString("wm.is.admin.sftpclient.pass.phrase." + userAlias));
				Session session = jsch.getSession(sftpUserAlias.getUserName(), sftpServerAlias.getHostName(), sftpServerAlias.getPort());
				session.setPassword(retrivePasswordAsString("wm.is.admin.sftpclient.password." + userAlias));
				session.setHostKeyAlias(sftpUserAlias.getSftpServerAlias());
				
				//Initialize Session config map 
				Properties config = new Properties();
				config.put("kex", sftpUserAlias.getPreferredKeyExchangeAlgo());
				String compression = "none";
				if ("zlib".equals(sftpUserAlias.getCompression())) {
					compression = "zlib,none";
				}
				config.put("compression.s2c", compression);
				config.put("compression.c2s", compression);
				config.put("compression_level", String.valueOf(sftpUserAlias.getCompressionLevel()));
				config.put("MaxAuthTries", String.valueOf(sftpUserAlias.getNoOfRetries()));
				config.put("StrictHostKeyChecking", "yes");
				config.put("PreferredAuthentications", "publickey,password");
				session.setConfig(config);
				
				//Connect to SFTP server
				session.connect();
				
				//Cache session key for reuse
				sessionKey = sftpSessionManager.addSession(session, sftpUserAlias.getSessionTimeout(), userAlias);
			} catch (Exception e) {
				throw new ServiceException(e);
			}
		}
		
		pipelineMap.put("sessionKey", sessionKey);
		pipelineMap.put("returnCode", "0");
		pipelineMap.put("returnCode", new MessageFormatter(msgBundle).format(147, 2, new Object[0]));
		// --- <<IS-END>> ---

                
	}

	// --- <<IS-START-SHARED>> ---
	private static SFTPSessionManager sftpSessionManager = SFTPSessionManager.getInstance();  
	private static SFTPClientManager sftpClientManager = SFTPClientManager.getInstance();
	private static Resources resources = new Resources(Server.getHomeDir(), true);
	private static File identitiesDir = resources.getDir(resources.getSFTPDir(), "identities");
	private static ResourceBundle msgBundle = ResourceBundle.getBundle(WmPublicMsgBundle.class.getName());
	
	private static SFTPUserAlias retrieveUserAlias(String userAlias) throws SFTPClientException, ValidationException{
		IData getUserAliasInput = IDataFactory.create();
		IDataMap getUserAliasInputMap = new IDataMap(getUserAliasInput);
		getUserAliasInputMap.put("alias", userAlias);
		return sftpClientManager.getUserAlias(getUserAliasInput);
	}
	
	private static SFTPServerAlias retrieveServerAlias(String serverAlias) throws SFTPClientException, ValidationException{
		IData getServerAliasInput = IDataFactory.create();
		IDataMap getServerAliasInputMap = new IDataMap(getServerAliasInput);
		getServerAliasInputMap.put("alias", serverAlias);
		return sftpClientManager.getServerAliasInfo(getServerAliasInput);
	}
	
	private static HostKeyRepository getHostKeyRepository() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException{
		Field field = SFTPClientManager.class.getDeclaredField("sftpSvrAliasManager");
		field.setAccessible(true);
		return (HostKeyRepository)field.get(sftpClientManager);
	}
	
	private static String retrivePasswordAsString(String passHandle) throws PasswordManagerException{
		String password = null;
		if (passHandle != null){
			PasswordManager passman = OutboundPasswordStore.getStore();
			WmSecureString secureString = passman.retrievePassword(passHandle);
			password = secureString.toString();
		}
		return password;
	}
	
	private static String getPrivateKeyFile(String keyFilename){
		return keyFilename == null ? null : new File(identitiesDir, keyFilename).getAbsolutePath();
	}
		
	// --- <<IS-END-SHARED>> ---
}

