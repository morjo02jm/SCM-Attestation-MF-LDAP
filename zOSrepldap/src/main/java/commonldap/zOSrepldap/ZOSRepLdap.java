package commonldap.zOSrepldap;

import java.sql.*;
import java.util.*;
import java.io.*;
import org.json.*;

import commonldap.commonldap.CommonLdap;
import commonldap.commonldap.JCaContainer;
import commonldap.commonldap.SDTicket;

public class ZOSRepLdap {
	private static int iReturnCode = 0;
	private static CommonLdap frame;
	private static String sProblems = "";
	private static List<String> ticketProblems = new ArrayList<String>();

	// Repository container headings	
	private static String sTagProject = "PRODUCT";
	private static String sTagContact = "CONTACT";
	private static String sTagApp     = "APP";
	
	// LDAP columns
	private static String sTagPmfkey  = "sAMAccountName";
	
	// Notification
	static String tagUL = "<ul> ";
	
	// JDBC
	private static String sDB2 = "jdbc:db2://usilca31.ca.com:5220/PP0ADB2"; // "jdbc:db2://CA31:5122/DA0GPTIB"; 

	ZOSRepLdap() {
		// Leaving empty		
	}

	private static String buildDsnCiaQuery(String sProduct,
			                               String stemMaster,
			                               boolean isDSN,
			                               boolean isVMVSE,
			                               String sVMVSEMaster)
	{
		String[] stems = null;
		List<String> locations = new ArrayList<String>();
		List<String> types = new ArrayList<String>();
		
		boolean stemsExist = false;
		boolean locationsExist = false;

		String permQueryRoleTemplate1 =  "SELECT DISTINCT "
				+ "P1.RESCLASS AS APP, " 
				+ "P1.SYSID AS APP_INSTANCE,"
				+ "\'"+sProduct+"\' AS PRODUCT,"
			  		+ "SUBSTR(R1.USERID,1,8) AS USERID, "                             
			  		+ "P1.AUTHTYPE, "                                                  
			  		+ "SUBSTR(P1.AUTHID,1,8) AS ROLEID, "                             
			  		+ "SUBSTR(P1.RESMASK,1,44) AS RESMASK, "
			  		+ "P1.ACC_READ, "
			  		+ "P1.ACC_WRITE, "
			  		+ "P1.ACC_UPDATE, "
			  		+ "P1.ACC_ALL, "
			  		+ "P1.ACC_NONE, "
			  		+ "P1.ACC_CREATE, "
			  		+ "P1.ACC_FETCH, "
			  		+ "P1.ACC_SCRATCH, "
			  		+ "P1.ACC_CONTROL, "
			  		+ "P1.ACC_INQUIRE, "
			  		+ "P1.ACC_SET, "
			  		+ "P1.ADMINBY, "
			  		//+ "P1.ADMINDATE, "
			  		//+ "P1.ADMINTIME, "
			  		+ "U1.NAME "
				  + "FROM "                                                                 
				  		+ "TABLE(CAIESQ.CIA_RESOURCE_MATCH('";

		String permQueryUserTemplate1 = "SELECT DISTINCT "
				+ "P2.RESCLASS AS APP, "
				+ "P2.SYSID AS APP_INSTANCE, "
				+ "\'"+sProduct+"\' AS PRODUCT,"
				+ "SUBSTR(P2.AUTHID,1,8) AS USERID, "                             
				+ "P2.AUTHTYPE, "                                                 
				+ "'   ' AS ROLEID, "                                              
				+ "SUBSTR(P2.RESMASK,1,44) AS RESMASK, "   
				+ "P2.ACC_READ, "
				+ "P2.ACC_WRITE, "
				+ "P2.ACC_UPDATE, "
				+ "P2.ACC_ALL, "
				+ "P2.ACC_NONE, "
				+ "P2.ACC_CREATE, "
				+ "P2.ACC_FETCH, "
				+ "P2.ACC_SCRATCH, "
				+ "P2.ACC_CONTROL, "
				+ "P2.ACC_INQUIRE, "
				+ "P2.ACC_SET, "
				+ "P2.ADMINBY, "
				//+ "P2.ADMINDATE, "
				//+ "P2.ADMINTIME, "
				+ "'   ' AS NAME "
			+"FROM "       
				+ "TABLE(CAIESQ.CIA_RESOURCE_MATCH('";

		//DSN		
		String permQueryRoleTemplate2a = 	 "','DATASET','%','PREFIX')) AS P1, "       
											+ "(CIADB01.ROLEXREF AS R1 INNER JOIN CIADB01.USERINFO AS U1 ON R1.USERID=U1.USERID AND R1.SYSID=U1.SYSID LEFT JOIN CIADB01.USERTSS AS T1 ON T1.SYSID=U1.SYSID AND T1.USERID=U1.USERID ) "                                           
										+"WHERE P1.SYSID = R1.SYSID "
										+"AND   P1.SYSID <> \'SYSC\' "
										+"AND   T1.ASUSPEND <> \'Y\' "
										+"AND   P1.AUTHID = R1.ROLEID ";
		
		
		String permQueryUserTemplate2a = 	 "','DATASET','%','PREFIX')) AS P2 LEFT JOIN CIADB01.USERTSS AS T2 ON T2.SYSID=P2.SYSID AND T2.USERID=P2.AUTHID "  
										+"WHERE P2.AUTHTYPE = 'U' "
				                        +"AND   T2.ASUSPEND <> \'Y\' "
										+"AND   P2.SYSID <> \'SYSC\' ";

		//VMVSE
		String permQueryRoleTemplate2b = 	 "','%','PREFIX')) AS P1, "       
						+ "(CIADB01.ROLEXREF AS R1 INNER JOIN CIADB01.USERINFO AS U1 ON R1.USERID=U1.USERID AND R1.SYSID=U1.SYSID LEFT JOIN CIADB01.USERTSS AS T1 ON T1.SYSID=U1.SYSID AND T1.USERID=U1.USERID ) "                                           
					+"WHERE P1.SYSID = R1.SYSID "
					+"AND   T1.ASUSPEND <> \'Y\' "
					+"AND   P1.AUTHID = R1.ROLEID ";

		String permQueryUserTemplate2b = 	 "','%','PREFIX')) AS P2 LEFT JOIN CIADB01.USERTSS AS T2 ON T2.SYSID=P2.SYSID AND T2.USERID=P2.AUTHID "  
					+"WHERE P2.AUTHTYPE = 'U' "
				    +"AND T2.ASUSPEND <> \'Y\' ";
						 
		String permQuery = "";
				
		if (isDSN && stemMaster != null && !stemMaster.contentEquals("Type:;SFS"))
		{
			stems = stemMaster.split("[;]");
			stemsExist = true;
			for (int i = 0; i < stems.length; i++)
			{
				stems[i] = stems[i].trim().toUpperCase();
				//System.out.println(stems[i]);
				if (stems[i].matches(".*[.][A-Z0-9@#$&*-+]{8}$"))
				{
					stems[i] = stems[i] + ".";
					//System.out.println(stems[i]);
				}
			}	
		}
		
		if (isVMVSE && !sVMVSEMaster.isEmpty()) {
			sVMVSEMaster = sVMVSEMaster.replace("\"[", "[");
			sVMVSEMaster = sVMVSEMaster.replace("]\"", "]");
			sVMVSEMaster = sVMVSEMaster.replace("\"\"", "\"");
			
			try {				
				JSONArray ja = new JSONArray(sVMVSEMaster);
				for (int j=0; j<ja.length(); j++) {
					String sLocation = ja.getJSONObject(j).getString("location");
					String sType = ja.getJSONObject(j).getString("type");
					locations.add(sLocation);
					types.add(sType);
					locationsExist = true;
				}
			}  catch (JSONException e) {
				iReturnCode = 1008;
			    frame.printErr(e.getLocalizedMessage());
			    System.exit(iReturnCode);		    							
			}
		}
		
		if (stemsExist)
		{
			for (int i = 0; i < stems.length; i++)
			{
				permQuery += permQueryRoleTemplate1 + stems[i] + permQueryRoleTemplate2a + " UNION ";
			}
										
			
			for (int i = 0; i < stems.length; i++)
			{
				permQuery += permQueryUserTemplate1 + stems[i] + permQueryUserTemplate2a; 
				if (i < stems.length - 1 || locationsExist) permQuery += " UNION ";
			}
		}
		
		if (locationsExist) {
			for (int i = 0; i < locations.size(); i++)
			{
				permQuery += permQueryRoleTemplate1 + locations.get(i) + "','" + types.get(i) + permQueryRoleTemplate2b + " UNION ";					
			}
			
			for (int i = 0; i < locations.size(); i++)
			{
				permQuery += permQueryUserTemplate1 + locations.get(i) + "','" + types.get(i) + permQueryUserTemplate2b; 
				
				if (i < locations.size() - 1) permQuery += " UNION ";
			}			
		}
				
		permQuery = permQuery + ";";

		return permQuery;
	} // buildDsnCiaQuery

		
	private static void readDBToRepoContainer(JCaContainer cRepoInfo, 
            								  String sDB2Password,
            								  String sQuery,
            								  String sProduct) {
		PreparedStatement pstmt = null; 
		String sqlStmt;
		int iIndex = cRepoInfo.getKeyElementCount("APP");
		ResultSet rSet;
		
		String sqlError = "DB2. Unable to execute query.";
		String sJDBC = sDB2+":retrieveMessagesFromServerOnGetMessage=true;emulateParameterMetaDataForZCalls=1;;user=ATTAUT1;password="+sDB2Password+";";
		
		try {
			Class.forName("com.ibm.db2.jcc.DB2Driver");
			Connection conn = DriverManager.getConnection(sJDBC);
			
			sqlError = "DB2. Error reading z/OS Dataset records from CIA database for Product: "+sProduct+".";
			sqlStmt = sQuery;
			pstmt=conn.prepareStatement(sqlStmt); 
			rSet = pstmt.executeQuery();

			while (rSet.next()) {
				String sAuthType = rSet.getString("AUTHTYPE").trim();
				String sRoleID = sAuthType.equalsIgnoreCase("R")? rSet.getString("ROLEID"): "";
				
				cRepoInfo.setString("APP",           rSet.getString("APP").trim(),                         iIndex);
				cRepoInfo.setString("APP_INSTANCE",  rSet.getString("APP_INSTANCE").trim(),                iIndex);
				cRepoInfo.setString("PRODUCT",       rSet.getString("PRODUCT").trim(),                     iIndex);
				cRepoInfo.setString("AUTHTYPE",      sAuthType,                                            iIndex);
				cRepoInfo.setString("ROLEID",        sRoleID.trim(),                                       iIndex);
				cRepoInfo.setString("RESMASK",       rSet.getString("RESMASK").trim(),                     iIndex);
				cRepoInfo.setString("CONTACT",       "",                                                   iIndex);
				cRepoInfo.setString("ADMINISTRATOR", rSet.getString("ADMINBY").toLowerCase().trim(), iIndex);
				//cRepoInfo.setString("DEPARTMENT",    rSet.getString("RESOURCE_OWNER").toLowerCase().trim(),iIndex);
				cRepoInfo.setString("USERID",        rSet.getString("USERID").toLowerCase().trim(),        iIndex);
				cRepoInfo.setString("USERNAME",      rSet.getString("NAME").trim(),                        iIndex);
				cRepoInfo.setString("ACC_READ",      rSet.getString("acc_read").trim(),                    iIndex);
				cRepoInfo.setString("ACC_WRITE",     rSet.getString("acc_write").trim(),                   iIndex);
				cRepoInfo.setString("ACC_UPDATE",    rSet.getString("acc_update").trim(),                  iIndex);
				cRepoInfo.setString("ACC_ALL",       rSet.getString("acc_all").trim(),                     iIndex);
				cRepoInfo.setString("ACC_NONE",      rSet.getString("acc_none").trim(),                    iIndex);
				cRepoInfo.setString("ACC_CREATE",    rSet.getString("acc_create").trim(),                  iIndex);
				cRepoInfo.setString("ACC_FETCH",     rSet.getString("acc_fetch").trim(),                   iIndex);
				cRepoInfo.setString("ACC_SCRATCH",   rSet.getString("acc_scratch").trim(),                 iIndex);
				cRepoInfo.setString("ACC_CONTROL",   rSet.getString("acc_control").trim(),                 iIndex);
				cRepoInfo.setString("ACC_INQUIRE",   rSet.getString("acc_inquire").trim(),                 iIndex);
				cRepoInfo.setString("ACC_SET",       rSet.getString("acc_set").trim(),                     iIndex);			
				iIndex++;
			} // loop over record sets

			frame.printLog(">>>:"+iIndex+" Records Read From DB2, including Product: "+sProduct+".");

		} catch (ClassNotFoundException e) {
			iReturnCode = 101;
			frame.printErr(sqlError);
			frame.printErr(e.getLocalizedMessage());			
			System.exit(iReturnCode);
		} catch (SQLException e) {     
			iReturnCode = 102;
			frame.printErr(sqlError);
			frame.printErr(e.getLocalizedMessage());			
			System.exit(iReturnCode);
		}	
	} // readDBToRepoContainer	

	
	private static void writeDBFromRepoContainer(JCaContainer cRepoInfo, String sImagDBPassword) {
		PreparedStatement pstmt = null; 
		String sqlStmt;
		int iResult;
		
		String sqlError = "";
		String sJDBC = "jdbc:sqlserver://AWS-UQAPA6ZZ:1433;databaseName=GMQARITCGISTOOLS;user=gm_tools_user;password="+sImagDBPassword+";";
		String sqlStmt0 = "insert into GITHUB_REVIEW "+
	              "( Application, ApplicationLocation, EntitlementOwner1, EntitlementOwner2, EntitlementName, EntitlementAttributes, ContactEmail, User_ID, UserAttributes) values ";
		
		String sEntitlement2 = "";
		String sContactEmail = "";
		String sEntitlementAttrs = "";
		String sUserAttrs = "";
		String sValues = "";
		
		try {
			Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
			Connection conn = DriverManager.getConnection(sJDBC);
	
			String sApp = "Mainframe";
			String sApp2 = "DATASET";

			sqlError = "DB. Error deleting previous records.";
			sqlStmt = "delete from GITHUB_REVIEW where Application in ('"+ sApp +"','"+ sApp2 + "')";
			pstmt=conn.prepareStatement(sqlStmt);  
			iResult = pstmt.executeUpdate();
			if (iResult > 0) 
				frame.printLog(">>>:"+iResult+" Previous IMAG Feed Records Deleted.");
			
			sqlError = "DB. Error inserting record.";
			int nRecordsWritten = 0;
			int nBlock = 100;

			for (int iIndex=0,nRecords=0; iIndex<cRepoInfo.getKeyElementCount("APP"); iIndex++) {
				if (!cRepoInfo.getString("APP", iIndex).isEmpty()) { 
					if (nRecords%nBlock == 0)
						sqlStmt = sqlStmt0;
					else 
						sqlStmt += " , ";
					
					sEntitlement2 = cRepoInfo.getString("AUTHTYPE", iIndex).equalsIgnoreCase("U")? "User" : "Role:"+cRepoInfo.getString("ROLEID", iIndex);
					sContactEmail = "";
					String[] aContacts = frame.readAssignedApprovers(cRepoInfo.getString("CONTACT", iIndex));
					for (int j=0; j<aContacts.length; j++) {
						if (!sContactEmail.isEmpty())
							sContactEmail += ";";
						if (aContacts[j].equalsIgnoreCase("toolsadmin"))
							sContactEmail += "Toolsadmin@ca.com";
						else
							sContactEmail += aContacts[j]+"@ca.com";
					}
					sEntitlementAttrs = "adminby=" + cRepoInfo.getString("ADMINISTRATOR", iIndex);
					sUserAttrs = "username=" +  cRepoInfo.getString("USERNAME", iIndex).replace("\'", "") + ";" +
							     "read="     + (cRepoInfo.getString("ACC_READ", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "write="    + (cRepoInfo.getString("ACC_WRITE", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "update="   + (cRepoInfo.getString("ACC_UPDATE", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "all="      + (cRepoInfo.getString("ACC_ALL", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "none="     + (cRepoInfo.getString("ACC_READ", iIndex).equalsIgnoreCase("A")? "Y" : "N") ;
					
					String sProduct = cRepoInfo.getString("PRODUCT", iIndex);
					if (sProduct.length()>=100) {
						int cIndex = sProduct.indexOf(" (");
						sProduct = cIndex < 0? sProduct:sProduct.substring(0, cIndex);
					}
					sValues = "('"  + sApp + "',"+
							  "'"   + cRepoInfo.getString("APP_INSTANCE", iIndex) + "',"+
							  "'"   + sProduct + "',"+
							  "'"   + sEntitlement2 + "',"+
							  "'"   + cRepoInfo.getString("RESMASK", iIndex) + "',"+
							  "'"   + sEntitlementAttrs + "',"+
							  "'"   + sContactEmail + "',"+
							  "'"   + cRepoInfo.getString("USERID", iIndex) + "',"+
							  "'"   + sUserAttrs + "')";
					
				    sqlStmt += sValues;
				    
				    if (nRecords%nBlock == (nBlock-1)) {
						pstmt=conn.prepareStatement(sqlStmt);  
						iResult = pstmt.executeUpdate();
						if (iResult > 0) 
							nRecordsWritten += iResult;	
						sqlStmt = "";
				    }
					nRecords++;	
				}
			} // loop over records

			if (!sqlStmt.isEmpty()) {
				pstmt=conn.prepareStatement(sqlStmt);  
				iResult = pstmt.executeUpdate();
				if (iResult > 0) 
					nRecordsWritten += iResult;					
			}
			frame.printLog(">>>:"+nRecordsWritten+" Inserted Records Made to DB.");
		
		} catch (ClassNotFoundException e) {
			iReturnCode = 301;
		    frame.printErr(sqlError);
		    frame.printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);
		} catch (SQLException e) {     
			iReturnCode = 302;
		    frame.printErr(sqlError);
		    frame.printErr(e.getLocalizedMessage());			
		    System.exit(iReturnCode);
		}
	} // writeDBFromRepoContainer	
	
	
	
	public static void main(String[] args) {
		int iParms = args.length;
		int iReturnCode = 0;
		String sOutputFile = "";
		String sInputFile = "";
		String sUserFile = "";
		String sBCC = "";
		String sLogPath = "zOSrepldap.log";
		String sMapFile = "tss_user_mapping.csv";
		String sContactFile = "";
		String sDB2Password = "";
		String sImagDBPassword = "";	
		boolean bShowTerminated = false;
		
		// check parameters
		for (int i = 0; i < iParms; i++)
		{					
			if (args[i].compareToIgnoreCase("-inputfile") == 0 )
			{
				sInputFile = args[++i];
			}			
			else if (args[i].compareToIgnoreCase("-outputfile") == 0 )
			{
				sOutputFile = args[++i];
			}			
			else if (args[i].compareToIgnoreCase("-mapfile") == 0 )
			{
				sMapFile = args[++i];
			}			
			else if (args[i].compareToIgnoreCase("-contactfile") == 0 )
			{
				sContactFile = args[++i];
			}			
			else if (args[i].compareToIgnoreCase("-bcc") == 0 )
			{
				sBCC = args[++i];
			}			
			else if (args[i].compareToIgnoreCase("-log") == 0 )
			{
				sLogPath = args[++i];
			}	
			else if (args[i].compareToIgnoreCase("-showterminated") == 0 )
			{
				bShowTerminated = true;
			}	
			else {
				System.out.println("Argument: "+args[i]);
				System.out.println("Usage: zOSrepldap \n"+
				                   "                     -outputfile textfile \n"+
				                   "                     [-bcc emailadress] [-log textfile] [-h |-?]");
				System.out.println(" -inputfile option specifies the attestation input file to validate (tsv)");
				System.out.println(" -outputfile option specifies the attestation output file (csv)");
				System.out.println(" -showterminated option creates notifications for terminated users");
				System.out.println(" -bcc option specifies an email address to bcc on notifications sent to users");
				System.out.println(" -log option specifies location log file.");
				System.exit(iReturnCode);
			}
		} // end for
		
		JCaContainer cLDAP = new JCaContainer();
		frame = new CommonLdap("zOSrepldap",
        		                sLogPath,
        		                sBCC,
        		                cLDAP);
			
		try {	
			Map<String, String> environ = System.getenv();
	        for (String envName : environ.keySet()) {
	        	if (envName.equalsIgnoreCase("ENDEAVOR_DB_PASSWORD"))        
	        		sDB2Password = frame.AESDecrypt(environ.get(envName));
	        	if (envName.equalsIgnoreCase("IMAG_DB_PASSWORD"))        
	        		sImagDBPassword = frame.AESDecrypt(environ.get(envName));
	        }
	        
			JCaContainer cContact = new JCaContainer();
			if (!sContactFile.isEmpty())
				frame.sContactFile = sContactFile;
			frame.readSourceMinderContacts(cContact, "Mainframe", cLDAP);

			JCaContainer cRepoInfo = new JCaContainer();
			
			if (sInputFile.isEmpty()) {
				// loop over contact records
				for (int iIndex=0; iIndex<cContact.getKeyElementCount("Location"); iIndex++) {
					if (cContact.getString("Active", iIndex).contentEquals("Y")) {
						String sProduct    = cContact.getString("Product", iIndex);
						String sStemMaster = cContact.getString("Location", iIndex).trim();
						boolean isDSN   = cContact.getString("SourceResources", iIndex).contains("DSN");
						boolean isVMVSE = cContact.getString("SourceResources", iIndex).contains("VMVSE");
						String sVMVSEMaster = cContact.getString("VMVSELocation", iIndex).trim();

						if (!sStemMaster.isEmpty() &&
							!sStemMaster.equalsIgnoreCase("N/A") &&
							(isVMVSE || !sStemMaster.equalsIgnoreCase("Type:;SFS"))) 
						{					
							if (sStemMaster.contains("Directories:;")) {
								int cIndex = sStemMaster.indexOf("Directories:;");
								sStemMaster = sStemMaster.substring(cIndex+13);
							}
							String sQuery = buildDsnCiaQuery(sProduct, sStemMaster, isDSN, isVMVSE, sVMVSEMaster);
							readDBToRepoContainer(cRepoInfo, sDB2Password, sQuery, sProduct);
						}						
					}
				}
			} else {
				frame.readInputListGeneric(cRepoInfo, sInputFile, '\t');
			}
			
			// Set contact information
			for (int iIndex=0; iIndex<cContact.getKeyElementCount("Approver"); iIndex++) {
				String sLocation = cContact.getString("Location", iIndex).replace("\"", "");
				String sProject = cContact.getString("Product", iIndex);
				String[] sApprovers = frame.readAssignedApprovers(cContact.getString("Approver", iIndex));
				boolean bActive = cContact.getString("Active", iIndex).contentEquals("Y");
				//String sReleases = cContact.getString("Release", iIndex);
				
				String sApprover = "";
				for (int jIndex=0; jIndex<sApprovers.length; jIndex++) {
					if (!sApprover.isEmpty()) 
						sApprover += ";";
					sApprover += sApprovers[jIndex];
				}
				
				if (sApprover.isEmpty()) {
		    		if (sProblems.isEmpty()) 
		    			sProblems = tagUL;			    		
		    		sProblems+= "<li>The Mainframe product, <b>"+sProject+"</b>, has no valid contact.</li>\n";									
				}
				
				int[] iProjects = cRepoInfo.find("PRODUCT", sProject);
				
				for (int kIndex=0; kIndex<iProjects.length; kIndex++) {
					if (cRepoInfo.getString("CONTACT", iProjects[kIndex]).isEmpty())
						//cRepoInfo.setString("CONTACT", bActive? sApprover:"toolsadmin", iProjects[kIndex]);
						cRepoInfo.setString("CONTACT", sApprover, iProjects[kIndex]);
				}
			} // loop over contact records
			
			// check user ids
			JCaContainer cUsers = new JCaContainer();
			frame.readInputListGeneric(cUsers, sMapFile, ',');
			
			for (int iIndex=0; iIndex<cRepoInfo.getKeyElementCount(sTagApp); iIndex++) {
				String sProduct, sResmask, sAuthtype, sRoleid;
				if (!cRepoInfo.getString(sTagApp, iIndex).isEmpty()) {
					boolean bLocalGeneric=false;
					boolean bTerminated=false;

					String sID  = cRepoInfo.getString("USERID", iIndex);
					if (sID.contains("?")) 
						sID = sID.substring(0, sID.indexOf('?'));
					String sRealID = sID;
					String sUseID  = sID;

					int[] iRepl = cUsers.find("TOPSECRET", sID.toLowerCase());
					
					boolean bUnmapped = false;
					if (iRepl.length > 0) {
						sRealID = cUsers.getString("CADOMAIN", iRepl[0]);
						if (sRealID.equals("Generic")) {
							bLocalGeneric = true;
						}
						else {
							sUseID = sRealID;
						}
					}
					else {
						iRepl = cUsers.find("CADOMAIN",sID.toLowerCase());
						if (iRepl.length == 0)
							bUnmapped = true;
					}
					
					int[] iLDAP = cLDAP.find(sTagPmfkey, sUseID);
					
					if (iLDAP.length == 0 && !bLocalGeneric) {
			    		int[] iUsers = cRepoInfo.find("USERID", sID); 

			    		if (!bLocalGeneric) {
							for (int i=0; i<iUsers.length; i++) {
								String sApp = cRepoInfo.getString(sTagApp, iUsers[i]);
								if (!sApp.isEmpty()) {									
									if (bUnmapped) {
							    		if (sProblems.isEmpty()) 
							    			sProblems = tagUL;			    		
							    		sProblems+= "<li>The Mainframe dataset user id, <b>"+sID+"</b>, references an unmapped user.</li>\n";									
									}
									else {				
										if (bShowTerminated) {											
								    		if (sProblems.isEmpty()) 
								    			sProblems = tagUL;			    		
								    		sProblems+= "<li>The Mainframe SCM user id, <b>"+sID+"</b>, references a terminated user.</li>\n";									
										}
									}
									
						    		String sSysIdArr = "{";
						    		for (int j=i; j<iUsers.length; j++) {
						    			String sSysId = cRepoInfo.getString("APP_INSTANCE", iUsers[j]);
						    			if (!sSysIdArr.contains(sSysId)) {
						    				sSysIdArr += (i==j?"":";") + sSysId;
						    			}
						    			cRepoInfo.setString(sTagApp, "", iUsers[j]);
						    		}
						    		sSysIdArr += "}";
						    		
					    			if (bShowTerminated) {
					    				ticketProblems.add("USERTSS.ASUSPEND should be set for TSS user id, "+sID+", with SYSIDs, "+sSysIdArr+".");
					    			}
								} // next unprocessed entry
							} // loop over users with no corporate id
			    		}
					} 
					else if (bLocalGeneric || !sID.equalsIgnoreCase(sRealID)){
			    		int[] iUsers = cRepoInfo.find("USERID", sID); 	
			    		for (int i=0; i<iUsers.length; i++) {
			    			cRepoInfo.setString("USERID", 
			    					            (bLocalGeneric? sUseID+"?" : sUseID),
			    					            iUsers[i]);
			    		}
					}
					
					if (bUnmapped && !bLocalGeneric && iLDAP.length > 0) {
						int cIndex = cUsers.getKeyElementCount("CADOMAIN");
						cUsers.setString("TOPSECRET", sID, cIndex);
						cUsers.setString("CADOMAIN", sUseID.toLowerCase(), cIndex);
					}
				}
			} // loop over assignments
			
			// Write out tss mapping file with changes
			if (!cUsers.isEmpty()) {
				frame.writeCSVFileFromListGeneric(cUsers, sMapFile, ',', null, false);
			}
			
			// Write out processed repository in organization file
			if (!sOutputFile.isEmpty()) {
				frame.writeCSVFileFromListGeneric(cRepoInfo, sOutputFile, '\t', cLDAP);					
			}
			
			// Write out processed records to database
			writeDBFromRepoContainer(cRepoInfo, sImagDBPassword);
			
			if (!sProblems.isEmpty()) {
				String email = frame.expandDistributionListforEmail("cn=Team - GIS - githubcom - Tools Services - Contacts,ou=self service groups,ou=groups", cLDAP);
				String sSubject, sTicket, sScope;
				if (email.startsWith(";"))
					email = email.substring(1); 
				
				if (sProblems.contains("terminated user")) {
					email = email+";bigag01@ca.com"; //Team-GIS-Mainframe-PlatformManagement-Security?
				}
				
				sSubject = "Notification of Mainframe SCM Governance Problems and Changes";
				sScope = "CIA DB2 Database";
				sTicket = "Mainframe:System Mainframe-Other SCM User Access";
				
				
		        //create a service desk ticket from ticketProblem
				frame.createServiceTicket(sProblems, sTicket, ticketProblems, "GIS-STO-Mainframe-Management-L2", "");
				
				sProblems+="</ul>\n";				
		        String bodyText = frame.readTextResource("Notification_of_Noncompliant_Mainframe_Contacts.txt", sScope, sProblems, "", "");								        								          
		        frame.sendEmailNotification(email, sSubject, bodyText, true);
			} // had some notifications
			
	     } catch (Exception e) {
				iReturnCode = 1;
			    frame.printErr(e.getLocalizedMessage());			
			    System.exit(iReturnCode);		    	    	 
	     }	// try/catch blocks         
	}
}
	
