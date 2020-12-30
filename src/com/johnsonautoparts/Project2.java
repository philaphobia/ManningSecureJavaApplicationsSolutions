package com.johnsonautoparts;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Hashtable;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;

import org.w3c.dom.Document;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


import com.johnsonautoparts.exception.AppException;
import com.johnsonautoparts.logger.AppLogger;

/**
 * 
 * Project2 class which contains all the method for the milestones. The task number 
 * represents the steps within a milestone.
 * 
 * Each method has a name which denotes the type of security check we will be fixing.
 * There are several fields in the notes of each method:
 * 
 * TITLE - this is a description of code we are trying to fix
 * RISK - Some explanation of the security risk we are trying to avoid
 * ADDITIONAL - Further help or explanation about work to try
 * REF - An ID to an external reference which is used in the help of the liveProject
 * 
 */
public class Project2 extends Project {
	
	public Project2(Connection connection, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
		super(connection, httpRequest, httpResponse);
	}
	
	
	/**
	 * Project 2, Milestone 1, Task 1
	 * 
	 * TITLE: Protect the database from SQL injection
	 * 
	 * RISK: The id is received as a parameter from the website without any sanitization and placed
	 *       directly into a SQL query. This opens the method up to SQL injection if the user includes
	 *       a single quote to terminate the id and then adds their own clauses after.
	 * 
	 * REF: CMU Software Engineering Institute IDS00-J
	 * 
	 * @param query
	 * @return String
	**/
	public int dbInventory(String idStr) throws AppException {
		if (connection == null) {
	        throw new AppException("dbQuery had stale connection","application error");
		}
		
		try {
			/**
			 * SOLUTION: The id parameter comes directly from the request parameter in ServletHandler
			 *           and passed to the method without any sanitization. The id parameter is then placed
			 *           directly into a SQL command which is a classic case of SQL injection. If the malicious
			 *           user includes a single quote (') then the WHERE id clause is closed and extra
			 *           SQL can be added. Some databases allow multiple commands on a single line if they
			 *           are separate with semicolons.
			 *           
			 *           The following lines are commented out and a PrepareStatement is used which serves two
			 *           purposes: it helps filter out SQL special characters and parameterizes data to force
			 *           the content into specific data types. Instead of the variable placed directly in the
			 *           SQL command, a question mark (?) is used ant the setString(), setInt(), etc replace
			 *           the value when the statement is executed
			 *
			 * String sql = "SELECT COUNT(id) FROM inventory WHERE id = '" + id + "'";
			 * Statement stmt = connection.createStatement();
			 * ResultSet rs = stmt.executeQuery(sql);
		     */
			
			String sql = "SELECT COUNT(id) FROM inventory WHERE id = ?";
			try (PreparedStatement stmt = connection.prepareStatement(sql) ) {
				
				//force the id into an integer by casting and catching any exceptions
				int id=0;
				try {
					id = Integer.parseInt(idStr);
				}
				catch(NumberFormatException nfe) {
					throw new AppException("dbInventory failed to parse integer: " + nfe.getMessage(), "application error");
				}
			
				stmt.setInt(1, id);

				try (ResultSet rs = stmt.executeQuery() ) {
					//SOLUTION END

					//return the count
					if (rs.next()) {
						return rs.getInt(1);
					}
					else {
						throw new AppException("dbInventroy did not return any results", "application error");
					}
				}//end resultset
			}//end statement
	   
		} catch (SQLException se) {
			throw new AppException("dbInventroy caught SQLException: " + se.getMessage(), "application error");
		} 
		finally {
			try {
				connection.close();
			} 
			catch (SQLException se) {
				AppLogger.log("dbInventory failed to close connection: " + se.getMessage());
			}
		}
	}
	
	
	/**
	 * Project 2, Milestone 1, Task 2
	 * 
	 * TITLE: Avoid SQL injection protection errors
	 * 
	 * RISK: The id is received as a parameter from the website without any sanitization and placed
	 *       directly into a SQL query. The developer attempted to protect from SQL injection by using a
	 *       PreparedStatement which adds additional security compared to the previous task, but it is
	 *       still not correct.
	 * 
	 * REF: CMU Software Engineering Institute IDS00-J
	 * 
	 * @param taskName
	 * @return String
	**/
	public int dbTasks(String taskName) throws AppException {
		if (connection == null) {
	        throw new AppException("dbTasks had stale connection","application error");
		}
		
		try {
			
			/**
			 * SOLUTION: As we learned in the previous task, PreparedStatement helps protect against SQL
			 *           injection. A common problem is developers use PreparedStatement but still use
			 *           the variable in a dynamic SQL string. This does not provide full protection
			 *           against SQL injection. You still need to add the question mark (?) and 
			 *           setString(), setInt(), etc for full parameterization.
			 * 
			 *           The following lines are commented out and the SQL string is fixed to add 
			 *           the parameter via setString()
			 *
			 * String sql = "SELECT COUNT(tasks) FROM schedule WHERE task_name = '" + taskName + "'";
			 * PreparedStatement stmt = connection.prepareStatement(sql);
			 */
			
			String sql = "SELECT COUNT(task_name) FROM schedule WHERE task_name = ?";
			try( PreparedStatement stmt = connection.prepareStatement(sql) ) {
				stmt.setString(1, taskName);
				//SOLUTION END
			
				try( ResultSet rs = stmt.executeQuery() ) {
	   
					// return the count
					if (rs.next()) {
						return rs.getInt(1);
					}
					else {
						throw new AppException("dbTasks did not return any results", "application error");
					}
				}//end resultset
			}//end preparedstatement
	   
		} catch (SQLException se) {
			se.printStackTrace();
			throw new AppException("dbTasks caught SQLException: " + se.getMessage(), "application error");
		} 
		finally {
			try {
				connection.close();
			} 
			catch (SQLException se) {
				AppLogger.log("dbTasks failed to close connection: " + se.getMessage());
			}
		}
	}
	
	
	/**
	 * Project 2, Milestone 1, Task 3
	 * 
	 * TITLE: Safe naming for files
	 * 
	 * RISK: Filenames accepted from user input could allow for inject attacks and read/writing
	 *       arbitrary files. For the existing step we will work on the filename and in the next
	 *       task you will work on securing the path to a file.
	 * 
	 * REF: CMU Software Engineering Institute IDS50-J
	 * 
	 * @param str
	 * @return String
	 */
	public void createFile(String fileName) throws AppException {
		final String tempPath = "temp" + File.separator + "upload" + File.separator;
		
		HttpSession session = httpRequest.getSession();
		String content = null;
		
		//make sure session_data contains data
		if( session.getAttribute("session_data") == null) {
			throw new AppException("session_data is empty", "application error");
		}
		
		//make sure session_data is text
		if(session.getAttribute("session_data") instanceof String) {
			content = (String)session.getAttribute("session_data");
		}
		else {
			throw new AppException("session_data does not contain text", "application error");
		}
		

		/**
		 * For the current task, do not worry about fixing makeSafePath()
		 * This is an exercise for the next task. The current task is to only focus
		 * on creating a safe filename
		 */
		//full path to file to be created
		String filePath = null;
		try {
			/*
			 * SOLUTION: remove special characters and potentially dangerous characters such as periods
			 *           which could be part of a double dot operating system attack. Whitelist a specific
			 *           set of alphanumeric characters and replace them with the underscore character
			 */
			String sanitizedFilename = fileName.replaceAll("[^A-Za-z0-9]","_");
			//SOlUTION END
			
			//check the path
			filePath = makeSafePath(tempPath + sanitizedFilename);
		}
		catch(IOException ioe) {
			throw new AppException("makeSafePath threw an IO error: " + ioe.getMessage(), "application error");
		}

		
		//write the session_data content to the file
		File f = new File(filePath);
		try (OutputStream out = new FileOutputStream(f) ) {
			out.write(content.getBytes(StandardCharsets.UTF_8));
		}
		catch(FileNotFoundException fnfe) {
			throw new AppException("createFile caught file not found: " + fnfe.getMessage(), "application error");
		}
		catch(IOException ioe) {
			throw new AppException("createFile caught IO error: " + ioe.getMessage(), "application error");
		}

	}
	
	
	/**
	 * Project 2, Milestone 1, Task 4
	 * 
	 * TITLE: Protecting file paths
	 * 
	 * RISK: A file path which includes input from a user can also contains malicious characters to perform
	 *       a bypass of file checks. The attacker could point to special files on the operating system
	 *       which would leak sensitive information.
	 * 
	 * REF: CMU Software Engineering Institute FIO16-J
	 * 
	 * @param str
	 * @return String 
	 */
	public String makeSafePath(String dirty) throws IOException {
		/**
		 * SOLUTION: The key to protecting paths is to first use Canonicalization. A malicious user may still
		 *           be able to pass special characters or redirect the file to special nodes on the operating
		 *           system. Other methods of attack could be to point at links or shortcuts. In the File class,
		 *           the method .getCanonicalPath() renders the path by following all links or other special
		 *           files and returns the path to the final file. Using this method, you can then check the
		 *           file type
		 *           
		 *           the following line is commented out and replace with more extensive checks
		 *
		 * return dirty.replaceAll("\\.\\." + File.separator,"_");
		 */
		String whitelistDirectory = "/uploads";
		int symlinkDepth =1; //set an explicit number of symbolic links allowed to follow
		
		//check if our string contains content
		if(dirty == null || dirty.trim().isEmpty()) {
			throw new IOException("path is null or empty");
		}
		
		//get a file version and generate a canonical path to resolve the actual file
		File f = new File(dirty);
		
		// REF: CMU SEI FIO00-J
		// set a specific number of symbolic links allowed to follow
		if (symlinkDepth <=0) {
			throw new IOException("path has too many symbolic links to follow");
		}
		
		//check if the file is in our safe path
		String canonicalPath = f.getCanonicalPath();

		if( canonicalPath.indexOf(whitelistDirectory) != 0) {
			throw new IOException("canonical path not in our safe directory");
		}
		
		//shouldn't reach this point but providing other methods of verifying a file
		//to make sure the file doesn't point to a special device
		Path filePath = f.toPath();
		if(Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS)) {
			throw new IOException("path points to a special device");
		}
		
		//other checks are possible for research on the topic
		//return the canonical path of the file
		return canonicalPath;
		
		//SOlUTION END
	}
	
	
	/**
	 * Project 2, Milestone 1, Task 5
	 * 
	 * TITLE: Safe extraction of compressed files
	 * 
	 * RISK: Zip files can be used as an attack vector to overcome resources on a system and create
	 *       a denial of service. An example is a zip bomb which contains recursive files which when
	 *       extracted can fill up almost any modern disk storage. The size of entries need to checked
	 *       against a pre-established maximum size that the system will accept
	 * 
	 * REF: CMU Software Engineering Institute IDS04-J
	 * 
	 * @param str
	 * @return String
	 */
	public String unzip(String fileName) throws AppException {
		final int BUFFER = 512;
		final int OVERFLOW = 0x1600000; // 25MB
		final int TOOMANY = 1024; //SOLUTION: max number of files which can be included in a zip
		
		final String tempPath = "temp" + File.separator + "zip";
		String zipPath = tempPath + File.separator + fileName + File.separator;
		
		try (FileInputStream fis = new FileInputStream(fileName)) {
			try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(fis)) ) {
				ZipEntry entry;

				/**
				 * SOLUTION: A zip bomb can exhaust system resources by forging the real file size
				 *           or extracting too many files. We need variables to track both of these
				 *           so will be using entries and total
				 */
				int entries = 0;
				long total = 0L;
				//SOLUTION END
				
				//go through each entry in the file
				while ((entry = zis.getNextEntry()) != null) {
					AppLogger.log("Extracting zip from filename: " + fileName);
					int count;
					byte data[] = new byte[BUFFER];
					
					/**
					 * SOLUTION: The getSize() entry can be tricked into reporting a false size
					 *           so we cannot use it. We will instead track the data size extracted
					 *           with a running sum in the variable total
					 *           
					 *           the following lines are commented out
					 *
					 * //avoid zip bombs by only allowing reasonable size files
					 * if (entry.getSize() > OVERFLOW ) {
					 * 		throw new IllegalStateException("zip file exceed max limit");
					 * }
					 * //look for illegal size which may be a hint something is wrong
					 * if (entry.getSize() == -1) {
					 *		throw new IllegalStateException("zip file entry returned inconsistent size and may be a zip bomb");
					 *}
					 *
					 */
					//we are also adding a method to track if the zip file is extracting outside our
					//expected directory
					String name = validateFilename(entry.getName(), ".");
					
					//check if a directory is in the zip
					if (entry.isDirectory()) {
						File f = new File(name);
						f.mkdir();
						continue;
					}
					//SOUTION END
					
					//output file is path plus entry
					try (FileOutputStream fos = new FileOutputStream(zipPath + entry.getName()) ) {
						try (BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER) ) {
					
							/**
							 * SOLUTION: we need to track the size of data extracted in the while
							 * 
							 * commented out the following lines and change the while condition
							 *
							 * while ((count = zis.read(data, 0, BUFFER)) != -1) {
							 *		dest.write(data, 0, count);
							 * }
							 * 
							 */
							while (total + BUFFER <= OVERFLOW && (count = zis.read(data, 0, BUFFER)) != -1) {
								dest.write(data, 0, count);
								total += count;
							}
							//SOLUTION END
					
							dest.flush();
					
							zis.closeEntry();
					
							/**
							 * SOLUTION: need the check for the number of files
							 *           and data size extracted
							 */
							entries++;
							if (entries > TOOMANY) {
								throw new IllegalStateException("Too many files to unzip.");
							}
							if (total + BUFFER > OVERFLOW) {
								throw new IllegalStateException("File being unzipped is too big.");
							}
							//SOLUTION END
						}//end bufferedoutputstream
					}//end fileoutputstream
				      
				} //end while entry
				
			}//end try zis
			catch(IllegalStateException ise) {
				throw new AppException("unzip caught strange behavior on zip file: " + ise.getMessage(), "application error");
			}
			catch(IOException ioe) {
				throw new AppException("unzip caught IO error: " + ioe.getMessage(), "application error");
			}
			
		}//end fis
		catch (FileNotFoundException fnfe) {
			throw new AppException("unzip caught file not found exception: " + fnfe.getMessage(), "application error");
		}
		catch (IOException ioe) {
			throw new AppException("unzip caught IO error: " + ioe.getMessage(), "application error");
		}

		//directory to the extracted zip
		return zipPath;
	}

	/**
	 * SOLUTION for Milestone 1, Task 5
	 * 
	 * Adding the following method for task 5
	 * 
	 */
	private String validateFilename(String filename, String intendedDir) throws IOException {
		if(filename == null || filename.trim().isEmpty()) {
			throw new IOException("filename is null or empty");
		}
		
		//establish file and canonical path of the zip entry filename
		File f = new File(filename);
		String canonicalPath = f.getCanonicalPath();
		
		//establish file and canonical path of where we were expecting the file to extract
		File id = new File(intendedDir);
		String idCanonicalPath = id.getCanonicalPath();
		
		//they should be the same or throw an error
		if(canonicalPath.startsWith(idCanonicalPath)) {
			return canonicalPath;
		}
		else {
			throw new IllegalStateException("File is outside the expected path");
		}
	}
	//SOLUTION Milestone 1, Task 5 END
	
	
	/**
	 * Project 2, Milestone 1, Task 6
	 * 
	 * TITLE: Sanitize data used in exec()
	 * 
	 * RISK: You should avoid using exec() unless no other alternatives are possible because injection
	 *       attacks allow code execution.
	 *       
	 * REF: CMU Software Engineering Institute IDS07-J
	 * 
	 * @param cmd
	 * @return String
	 */
	public String exec(String cmd) throws AppException {
		try {
			/**
			 * SOLUTION: sanitize the cmd to only allow a specific set of characters
			 *           avoid allowing characters such as periods to stop .. attacks.
			 *           This is just a simple solution and still could open the application
			 *           up to attacks.
			 */
			if (!Pattern.matches("[0-9A-Za-z]+", cmd)) {
				throw new AppException("exec was passed a cmd with illegal characters", "application error");
			}
			//SOLUTION END
			
			/** 
			 * SOLUTION: Another possible solution offered by CMU SEI IDS07-J is to
			 *           create an explicit whitelist of coomands allowed. For example the
			 *           method would use a switch to pick the program
			 *           
			 *           switch(cmd) {
			 *           	case 'list':
			 *           		execCmd = "ls";
			 *           		break;
			 *           
			 *           	case 'processes':
			 *           		execCmd = "ps";
			 *           		break;
			 *           
			 *           	default:
			 *           		throw new AppException("exec was send an illegal cmd");
			 *           }
			 *           
			 *           Runtime rt = Runtime.getRuntime();
			 *           Process proc = rt.exec(new String[] execCmd);
			 */
			
			Runtime rt = Runtime.getRuntime();
			Process proc = rt.exec(new String[] {"sh", "-c", cmd + " "});
			int result = proc.waitFor();
	    
			if (result != 0) {
				throw new AppException("process error: " + result, "application error");
			}
	    	InputStream in = proc.getInputStream();
	    	
			StringBuilder strBuilder = new StringBuilder();
			int i;

			while ((i = in.read()) != -1) {
				strBuilder.append( (char) i );
			}
	    
			return strBuilder.toString();
		}
		catch(IOException ioe) {
			throw new AppException("exec caught IO error: " + ioe.getMessage(), "application error");
		}
		catch(InterruptedException ie) {
			throw new AppException("exec caught interupted error: " + ie.getMessage(), "application error");
		}
	}
	
	
	/**
	 * Project 2, Milestone 1, Task 7
	 * 
	 * TITLE: Sanitize data used in JavaScript engine
	 * 
	 * RISK: The ScriptEnginer in Java provides a JavaScript engine for interpreting code and executing.
	 *       Passing untrusted text with sanitization could allow and attacker to run code which executes
	 *       on the operating system in the internal network.
	 *       
	 * REF: CMU Software Engineering Institute IDS52-J
	 * 
	 * @param cmd
	 * @return String
	 */
	public String evalScript(String printMessage) throws AppException {
		/**
		 * SOLUTION: Since code execution of untrusted user data is a critical risk, the data
		 *           passed to the execution engine must be thoroughly check to for the type of
		 *           data expected.
		 *           
		 *           In the existing case, we are only expecting a string of text to print, so
		 *           only allow basic alphanumeric
		 */
		if (!printMessage.matches("[\\w]*")) {
			// String does not match whitelist characters
			throw new IllegalArgumentException("evalScript was passed illegal characters");
		}
		//SOLUTION END
		
		/**
		 * SOLUTION: In the exception cases where special characters or other possible data
		 *           which cannot be filtered out with a basic regex expression, you should
		 *           use the lessons learned in the previous project for encoding HTML and script
		 *           data to sanitize.
		 *           
		 *          // For example, normalize the data to remove unicode
		 *          String cleanStr =  Normalizer.normalize(str, Form.NFKC);
		 *          
		 *          // Use the OWASP Encoder project to remove special tags
		 *          sanitizedStr = Encode.forHtml(cleanStr);
		 *           
		 */
		try {
			ScriptEngineManager manager = new ScriptEngineManager();
			ScriptEngine engine = manager.getEngineByName("javascript");
			Object ret = engine.eval("print('<tag>"+ printMessage + "</tag>')");
			
			if(ret == null) {
				throw new AppException("ScriptEngine in evalScript returned null", "application error");
			}
			
			else if(ret instanceof String) {
				return (String)ret;
			}
			
			else {
				throw new AppException("Unknown object returned from evalScript: " + ret.getClass().toString(), "application error");
			}
		}
		catch(ScriptException se) {
			throw new AppException("evalScript caugth ScriptException: " + se.getMessage(), "application error");
		}
	}
	
	
	/**
	 * Project 2, Milestone 2, Task 1
	 * 
	 * TITLE: Prevent XML injection attacks
	 * 
	 * RISK: If a user can inject unchecked text which is processed by an XML parser
	 *       they can overwrite text or possibly gain unauthorized access to data fields.
	 *       The content placed into an XML document needs to be validated
	 * 
	 * REF: CMU Software Engineering Institute IDS16-J
	 * 
	 * @param str
	 * @return String
	 */
	public String createXML(String partQuantity) throws AppException {
		/**
		 * SOLUTION: similar to avoid SQL injection attacks, avoiding XML can uses strong typing
		 *           to check if the data is of the expected type.
		 *           
		 *           For example, the method is past a string which purports to be a representation
		 *           of an Integer, so attempt to cast it to an integer and throw and error.
		 */
		try {
			Integer.parseInt(partQuantity);
		}
		catch(NumberFormatException nfe) {
			throw new AppException("createXML was not passed a string representation of an integer: " + nfe.getMessage(), "application error");
		}
		//SOLUTION END
		
		String xmlContent = "<?xml version=\"1.0\"?>"
				    + "<item>\n"
					+ "<title>Widget</title>\n"
			        + "<price>500</price>\n" 
					+ "<quantity>" + partQuantity + "</quantity>"
					+ "</item>";

		Document doc = null;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			InputSource is = new InputSource(xmlContent);
			doc = builder.parse(is);
		}
		catch(SAXException se) {
			throw new AppException("createXML could not validate XML: " + se.getMessage(), "application error");
		}
		catch(ParserConfigurationException pce) {
			throw new AppException("createXML caught parser exception: " + pce.getMessage(), "application error");
		}
		catch(IOException ioe) {
			throw new AppException("createXML caught IO exception: " + ioe.getMessage(), "application error");
		}
		
		httpResponse.setContentType("application/xml");
		return(doc.toString());
	}
	
	
	/**
	 * Project 2, Milestone 2, Task 2
	 * 
	 * TITLE: Validate with XML schema
	 * 
	 * RISK: For more complex XML documents or when adding multiple fields, an XML schema
	 *       should be used to validate all of the content.
	 * 
	 * REF: CMU Software Engineering Institute IDS16-J
	 * 
	 * @param str
	 * @return String
	 */
	public Document validateXML(String xml) throws AppException {
		/**
		 * SOLUTION: comment out the basic factory which did not define a schema namespace
		 * 
		 * DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		 */
		//SOLUTION END
		
		final String xsdPath = "resources/schema.xsd";
		
		//the code for this XML parse is very rudimentary but is here for demonstration
		//purposes to work with XML schema validation
		try {
			/**
			 * SOLUTION: The existing code did not use an XSD to validate the XML.
			 * 
			 *           We will comment out the existing
			 *           
			 * DocumentBuilder builder = factory.newDocumentBuilder();
			 * InputSource is = new InputSource(new String(xml));
			 * return builder.parse(is);
			 */
			
			/**
			 * SOLUTION: The follow code will validate the content of the data in the XML
			 *           against the schema defined in the XSD
			 */

			SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = factory.newSchema(new File(xsdPath));
			Validator validator = schema.newValidator();
	            
			InputSource is = new InputSource(new String(xml));
				 
			validator.validate(new StreamSource(is.getByteStream()));
			
			//XML validated so return a Document object
			DocumentBuilderFactory xmlFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = xmlFactory.newDocumentBuilder();
			return builder.parse(is);
			//SOLUTION END
		}
		catch(SAXException se) {
			throw new AppException("validateXML could not validate XML: " + se.getMessage(), "application error");
		}
		catch(ParserConfigurationException pce) {
			throw new AppException("validateXML caught parser exception: " + pce.getMessage(), "application error");
		}
		catch(IOException ioe) {
			throw new AppException("validateXML caught IO exception: " + ioe.getMessage(), "application error");
		}
	}
	
	
	/**
	 * Project 2, Milestone 2, Task 3
	 * 
	 * TITLE: Protect against XML External Entity (XEE) attacks
	 * 
	 * RISK: If a user can add external entities to an XML document they could possibly execute
	 *       code on the operating system which opens the application to a critical risk.
	 * 
	 * REF: CMU Software Engineering Institute IDS17-J
	 * 
	 * @param str
	 * @return String
	 */
	public Document parseXML(String xml) throws AppException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		
		//the code for this XML parse is very rudimentary but is here for demonstration
		//purposes to configure the parse to avoid XEE attacks
		try {
			/**
			 * SOLUTION: There are several methods for blocking XEE attacks and they all rely
			 *           on setting features in the DocumentBuilderFactory before the
			 *           new DocumentBuilder method is called.
			 *           
			 *           If you are using separate libraries such as with Xerces, then you will
			 *           need to alter the features. You can research the topic as extract credit.
			 */
			//if you can disable DTDs completely then use this
			String FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
		    factory.setFeature(FEATURE, true);
		    
		    //block external entities
		    FEATURE = "http://xml.org/sax/features/external-general-entities";
		    factory.setFeature(FEATURE, false);
		    
		    //block external parameters
		    FEATURE = "http://xml.org/sax/features/external-parameter-entities";
		    factory.setFeature(FEATURE, false);
		    
		    //block external DTDs
		    FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
		    factory.setFeature(FEATURE, false);
		    
		    // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
		    factory.setXIncludeAware(false);
		    factory.setExpandEntityReferences(false);
		    //SOLUTION END
		    
			DocumentBuilder builder = factory.newDocumentBuilder();
			InputSource is = new InputSource(new String(xml));
			return builder.parse(is);
		}
		catch(ParserConfigurationException | SAXException xmle) {
			throw new AppException("parseXML caught exception: " + xmle.getMessage(), "application error");
		}
		catch(IOException ioe) {
			throw new AppException("parseXML caught IO exception: " + ioe.getMessage(), "application error");
		}
	}
	
	
	/**
	 * Project 2, Milestone 2, Task 4
	 * 
	 * TITLE: Avoid XPath injection
	 * 
	 * RISK: XPath queries can be used similar to SQL injection to force untrusted text into a query which is
	 *       parsed dynamically and can be used to bypass authentication or gain unauthorized access to data
	 * 
	 * REF: CMU Software Engineering Institute IDS53-J
	 * 
	 * Source code from: https://wiki.sei.cmu.edu/confluence/display/java/IDS53-J.+Prevent+XPath+Injection
	 * 
	 * @param str
	 * @return boolean
	 */
	public boolean xpathLogin(String userPass) throws AppException {
		//create a path to the webapp
		StringBuilder webappPath = new StringBuilder();
		webappPath.append(System.getProperty( "catalina.base" ));
		webappPath.append(File.separator + "webapps" + File.separator + "SecureCoding" + File.separator);
		
		//make sure the string is not null
		if(userPass == null) {
			throw new AppException("parseXPath given a null value", "application error");
		}
		
		try {
			//split the user and password string which was concatenated with a colon
			//we would normally do further checks on the values but are limiting check here to reduce the code
			String[] args = userPass.split(":");
			String username = args[0];
			String passHash = encryptPassword(args[1]);
			String userDbPath = webappPath.toString() + "resources/users.xml";
			
			//load the users xml file
			DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
			domFactory.setNamespaceAware(true);
			DocumentBuilder builder = domFactory.newDocumentBuilder();
			Document doc = builder.parse(userDbPath);

			/**
			 * SOLUTION: To protect XPath queries, we can use defensive measure similar to SQL injection
			 *           to not allow the direct injection of user controlled parameters into a query.
			 *           Instead, the query is defined with value placeholders and the actual values are
			 *           added with the addVariable() method of a custom resolver.
			 *           
			 *           Below the current method is a custom class called MapVariableResolver which is 
			 *           used to add the method addVariable() to the XPathVariableResolver
			 *           
			 *           The existing code is commented out
			 *
			 * //create an XPath query
			 * XPathFactory factory = XPathFactory.newInstance();
			 * XPath xpath = factory.newXPath();
			 * XPathExpression expr = xpath.compile("//users/user[username/text()='" +
			 *      username + "' and password/text()='" + passHash + "' ]");
			 *
			 */
			//create an XPath for the expression
			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			
			//create an instance of our custom resolver to add variables and set it to the xpath
			MapVariableResolver resolver = new MapVariableResolver();
			xpath.setXPathVariableResolver(resolver);
			
			//create the xpath expression with variables and map variables
			XPathExpression expression = xpath.compile("//users/user[username/text()=$username and password/text()=$password]");
			resolver.addVariable(null, "username", username);
			resolver.addVariable(null, "password", passHash);

			//login failed if no element was found
			if( expression.evaluate(doc, XPathConstants.NODE) == null) {
				return(false);
			}
            else {
            	return(true);
            }
			//SOLUTION END
		}
		catch(ParserConfigurationException | SAXException | XPathException xmle) {
			throw new AppException("xpathLogin caught exception: " + xmle.getMessage(), "application error");
		}
		catch(IOException ioe) {
			throw new AppException("xpathLogin caught IO exception: " + ioe.getMessage(), "application error");
		}
	}
	
	/**
	 * SOLUTION class for Milestone 2, Task 4
	 *          custom class to allow variables to be injected into path expression
	 *          
	 *          Code from: http://www.java2s.com/Code/Java/XML/implementsXPathVariableResolver.htm
	 */
	private static class MapVariableResolver implements XPathVariableResolver {
		private Hashtable variables = new Hashtable();

		public void addVariable(String namespaceURI, String localName, Object value) {
			addVariable(new QName(namespaceURI, localName), value);
		}

		public void addVariable(QName name, Object value) {
			variables.put(name, value);
		}

		public Object resolveVariable(QName name) {
			Object retval = variables.get(name);
			return retval;
		}
	}
	//SOLUTION END FOR MILESTONE 2, TASK4
	
	
	/**
	 * Project 2, Milestone 2, Task 5
	 * 
	 * 
	 * TITLE: Serialized object safety
	 * 
	 * RISK: Recently exploits have leveraged Java's automatic triggering of readObject to inject code execution
	 *       of a serialized object which uses another class with an exploit. Java objects should take care
	 *       when deserializing to understand the actual content before it is serialized into a Java object.
	 *       The exploit can allow code execution on the Java application server which can lead to total 
	 *       compromise.
	 * 
	 * REF: CMU Software Engineering Institute SER12-J
	 *      
	 * @param str
	 * @return String
	 */
	/*
	 * SOLUTION: Instead of returning a generic Object, the method now returns our expected WhitelistClass.
	 *           Additional information is provided below in the next SOLUTION section. At the end of the
	 *           the deserializeObject method we define a new class WhitelistObjectInputStream and WhitelistClass
	 *           which are used in the solution
	 *           
	 *           The following line is commented out and replace with an explicit return of a WhitelistClass
	 *
	 * public Object deserializeObject(String base64Str) throws AppException {
	 **/
	public WhitelistClass deserializeObject(String base64Str) throws AppException {
	//SOLUTION END
		if(base64Str == null) {
			throw new AppException("deserializeObject received null base64 string", "application error");
		}
		
		//decode the base64 string
		byte[]decodedBytes = null;
		try {
			decodedBytes = Base64.getDecoder().decode(base64Str);
		}
		catch(IllegalArgumentException iae) {
			throw new AppException("deserializeObject caught exception decoding base64: " + iae.getMessage(), "application error");
		}
		
	    //deserialize the object
	    try (ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes)) {
	    	
	    	/**
	    	 * SOLUTION: The reference below uses a custom class which extends an ObjectInputStream and overrides
	    	 *           the method resolveClass to provide read ahead of the object being deserialized before
	    	 *           the readObject() method is called. Using this technique, you can compare the class name
	    	 *           to a whitelist of the class you are expecting to deserialize. If the object being
	    	 *           deserialized is not an instance of the expected class, the method throws an exception.
	    	 *           
	    	 *           https://www.ibm.com/developerworks/library/se-lookahead/
	    	 *           
		  	 *           The previous code is commented out which used the standard ObjectInputStream and
	    	 *           replaced with out custom WhitelistObjectInputStream which also include a parameter
	    	 *           passed with the expected class to be deserialized - WhitelistClass. If the expected
	    	 *           class is not the object deserialized, then the WhitelistObjectInputStream thows
	    	 *           an InvalidClassException.
	    	 *           
	    	 * try (ObjectInputStream ois = new ObjectInputStream(bais)) {          
	    	 */
	    	try (WhitelistObjectInputStream ois = new WhitelistObjectInputStream(bais, WhitelistClass.class)) {
	    	//SOlUTION END
	    		return (WhitelistClass)ois.readObject();
	    	}
	    	catch(StreamCorruptedException sce) {
	    		throw new AppException("deserializedObject caugh stream exception: " + sce.getMessage(), "application error");
	    	}
	    	catch(ClassNotFoundException | InvalidClassException ce) {
	    		throw new AppException("deserializedObject caugh class exception: " + ce.getMessage(), "application error");
	    	}

	    }
	    catch(IOException ioe) {
	    	throw new AppException("deserializedObject caugh IO exception: " + ioe.getMessage(), "application error");
	    }

	}
	
	/**
	 * SOLUTION for Milestone 2, Task 5
	 * 
	 * The custom WhitelistObjectInput stream is used to override resolveClass() method to give us a chance
	 * to check the type of object being deserialized before the readObject is called and a malicious serialized
	 * payload is executed
	 * 
	 */
	private static class WhitelistObjectInputStream extends ObjectInputStream {
		private Class<?> whitelistClass;
		
		public WhitelistObjectInputStream(InputStream inputStream, Class<?> whitelistClass) throws IOException {
			super(inputStream);
			
			this.whitelistClass = whitelistClass;
	    }
	 
	    /**
	     * Only deserialize instances of our expected whitelisted class
	     */
	    @Override
	    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
	        if (!desc.getName().equals(whitelistClass.getName())) {
	        	throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
	        }
	        return super.resolveClass(desc);
	    }
	}
	
	/**
	 * Fictitious class used to demonstrate for deserialization
	 * 
	 */
	public class WhitelistClass {
		private String ssn;
		private String sessionId;
		
		public WhitelistClass(String ssn, String sessionId) {
			this.ssn = ssn;
			this.sessionId = sessionId;
		}
	
		public String getSsn() {
			return new String(ssn);
		}
		
		public boolean validateSession(String id) {
			return sessionId.equals(id);
		}
	}
	//SOLUTION END Milestone 2, Task 5
	
	
	/**
	 * The following method does not need to be assessed in the project and is only here as a helper function
	 * 
	 * Code copied from: https://rgagnon.com/javadetails/java-0596.html
	 * 
	 * @param b
	 * @return String
	 */
	private String encryptPassword(String password) throws AppException {
		
	    try
	    {
	        MessageDigest crypt = MessageDigest.getInstance("SHA-1");
	        crypt.reset();
	        crypt.update(password.getBytes(StandardCharsets.UTF_8));
	        
	        byte[] b = crypt.digest();
	        
			String sha1 = "";
			for (int i=0; i < b.length; i++) {
				sha1 += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
			}
			
	        return sha1;
	    }
	    catch(NoSuchAlgorithmException nse) {
	        throw new AppException("encryptPassword got algo exception: " + nse.getMessage(), "application error");
	    }

	}
	
}
