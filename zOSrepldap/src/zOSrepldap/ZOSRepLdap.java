package zOSrepldap;

import java.sql.*;
import java.util.*;
import java.io.*;

import commonldap.CommonLdap;
import commonldap.JCaContainer;

public class ZOSRepLdap {
	private static int iReturnCode = 0;
	private static CommonLdap frame;
// Repository container headings	
	private static String sTagProject = "PRODUCT";
	private static String sTagContact = "CONTACT";
	private static String sTagApp     = "APP";
	
	// LDAP columns
	private static String sTagPmfkey  = "sAMAccountName";
	
	// Notification
	static String tagUL = "<ul> ";

	ZOSRepLdap() {
		// Leaving empty		
	}

	private static String buildDsnCiaQuery(String sProduct,
			                               String stemMaster)
	{
		String[] stems = null;
		boolean stemsExist = false;
				
		if (stemMaster != null)
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
		
		String permQueryRoleTemplate2 = 	 "','DATASET','%','PREFIX')) AS P1, "       
											+ "(CIADB01.ROLEXREF AS R1 INNER JOIN CIADB01.USERINFO AS U1 ON R1.USERID=U1.USERID AND R1.SYSID=U1.SYSID) "                                           
										+"WHERE P1.SYSID = R1.SYSID "
										+"AND P1.SYSID <> \'SYSC\' "
										+"AND   P1.AUTHID = R1.ROLEID ";
		
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
		
		String permQueryUserTemplate2 = 	 "','DATASET','%','PREFIX')) AS P2 "  
										+"WHERE P2.AUTHTYPE = 'U' "
										+"AND   P2.SYSID <> \'SYSC\' ";
		
				 
		String permQuery = "";
		
		if (stemsExist)
		{
			for (int i = 0; i < stems.length; i++)
			{
				permQuery += permQueryRoleTemplate1 + stems[i] + permQueryRoleTemplate2 + " UNION ";
			}
										
			
			for (int i = 0; i < stems.length; i++)
			{
				permQuery += permQueryUserTemplate1 + stems[i] + permQueryUserTemplate2; 
				if (i < stems.length - 1) permQuery += " UNION ";
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
		String sJDBC = "jdbc:db2://CA31:5122/DA0GPTIB:retrieveMessagesFromServerOnGetMessage=true;emulateParameterMetaDataForZCalls=1;;user=ATTAUT1;password="+sDB2Password+";";
		
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
					sUserAttrs = "username=" +  cRepoInfo.getString("USERNAME", iIndex) + ";" +
							     "read="     + (cRepoInfo.getString("ACC_READ", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "write="    + (cRepoInfo.getString("ACC_WRITE", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "update="   + (cRepoInfo.getString("ACC_UPDATE", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "all="      + (cRepoInfo.getString("ACC_ALL", iIndex).equalsIgnoreCase("A")? "Y" : "N") + ";" +
							     "none="     + (cRepoInfo.getString("ACC_READ", iIndex).equalsIgnoreCase("A")? "Y" : "N") ;
					
					sValues = "('"  + sApp + "',"+
							  "'"   + cRepoInfo.getString("APP_INSTANCE", iIndex) + "',"+
							  "'"   + cRepoInfo.getString("PRODUCT", iIndex) + "',"+
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
		String sBCC = "";
		String sLogPath = "zOSrepldap.log";
		String sDB2Password = "";
		String sImagDBPassword = "";	
		String sProblems = "";
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
			frame.readSourceMinderContacts(cContact, "Mainframe");

			JCaContainer cRepoInfo = new JCaContainer();
			
			if (sInputFile.isEmpty()) {
				// loop over contact records
				for (int iIndex=0; iIndex<cContact.getKeyElementCount("Location"); iIndex++) {
					String sProduct    = cContact.getString("Product", iIndex);
					String sStemMaster = cContact.getString("Location", iIndex).trim();
					if (!sStemMaster.isEmpty() &&
						!sStemMaster.equalsIgnoreCase("N/A") &&
						!sStemMaster.equalsIgnoreCase("Type:;SFS")) {					
						if (sStemMaster.contains("Directories:;")) {
							int cIndex = sStemMaster.indexOf("Directories:;");
							sStemMaster = sStemMaster.substring(cIndex+13);
						}
						String sQuery = buildDsnCiaQuery(sProduct, sStemMaster);
						readDBToRepoContainer(cRepoInfo, sDB2Password, sQuery, sProduct);
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
				
				int[] iProjects = cRepoInfo.find("PRODUCT", sProject);
				
				for (int kIndex=0; kIndex<iProjects.length; kIndex++) {
					if (cRepoInfo.getString("CONTACT", iProjects[kIndex]).isEmpty())
						cRepoInfo.setString("CONTACT", bActive? sApprover : "toolsadmin", iProjects[kIndex]);
				}
			} // loop over contact records
			
			// Write out processed repository in organization file
			if (!sOutputFile.isEmpty()) {
				frame.writeCSVFileFromListGeneric(cRepoInfo, sOutputFile, '\t');					
			}
			
			// Write out processed records to database
			writeDBFromRepoContainer(cRepoInfo, sImagDBPassword);
			
			if (!sProblems.isEmpty()) {
				sProblems+="</ul>\n";
				String email = "faudo01@ca.com";
				String sSubject, sScope;
				
				sSubject = "Notification of Problematic zOS Database Contacts";
				sScope = "CIA DB2 Database";
				
		        String bodyText = frame.readTextResource("Notification_of_Noncompliant_Endevor_Contacts.txt", sScope, sProblems, "", "");								        								          
		        frame.sendEmailNotification(email, sSubject, bodyText, true);
			} // had some notifications
			
	     } catch (Exception e) {
				iReturnCode = 1;
			    frame.printErr(e.getLocalizedMessage());			
			    System.exit(iReturnCode);		    	    	 
	     }	// try/catch blocks         
	}
}
	
