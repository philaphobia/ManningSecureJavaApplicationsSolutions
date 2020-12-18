

package com.johnsonautoparts;

import java.io.*;
import java.math.BigInteger;
import java.sql.Connection;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.*;
import java.util.regex.*;

import javax.servlet.http.HttpServletRequestWrapper;

import org.owasp.encoder.Encode;

import com.johnsonautoparts.exception.AppException;
import com.johnsonautoparts.logger.AppLogger;

/**
 * 
 * Project1 class which contains all the method for the milestones. The task number 
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
public class Project1 extends Project {	
	
	public Project1(Connection connection, HttpServletRequestWrapper httpRequest) {
		super(connection, httpRequest);
	}


	/**
	 * Project 1, Milestone 1, Task 1
	 * 
	 * TITLE: Normalize strings before validation
	 * 
	 * RISK: Since the text is not normalized, the cleaning step
	 *       may not fix any injections of invalid characters
	 * 
	 * REF: CMU Software Engineering Institute IDS01-J
	 * 
	 * @param str
	 * @return String
	 */
	public String normalizeString(String str) {
		Pattern pattern = Pattern.compile("[<&>]");
		Matcher matcher = pattern.matcher(str);
		
		/**
		 * SOLUTION: normalize the string before performing check to remove Unicode
		 *           which can be used as an attack vector
		 */
		String cleanStr =  Normalizer.normalize(str, Form.NFKC);
		
		//variable str is potentially dirty with HTML or JavaScript tags
		if (matcher.find()) {
			cleanStr = str.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">", "&gt;");
		}
		
		/**
		 * SOLUTION: move this before the pattern matching since normalize() needs to 
		 */
		//cleanStr = Normalizer.normalize(cleanStr, Form.NFKC);
		return cleanStr;
	}
	
	
	/**
	 * Project 1, Milestone 1, Task 2
	 * 
	 * TITLE: Avoid leaking data with Format string
	 * 
	 * RISK: Attackers could inject formatting strings into variable
	 *       which the application will process and leak
	 * 
	 * REF: CMU Software Engineering Institute IDS06-J
	 * 
	 * @param str
	 * @throws IllegalStateException
	 */
	public String formatString(String str) throws IllegalStateException {
		Calendar cal =new GregorianCalendar();
		
		/**
		 * SOLUTION: Do not use untrusted input in the format string. Use
		 *           The format pattern to rend the untrusted content as a string
		 */
		//return String.format(str + " passed on date %t", cal);
		return String.format("%s passed on date %t", str, cal);
	}
	
	
	/**
	 * Project 1, Milestone 1, Task 3
	 * 
	 * TITLE: String modification before validation
	 * 
	 * RISK: An attacker may use Unicode or other special characters
	 *       which will help bypass filters, but are then removed later
	 *       and the attack succeeds. For example, text passed as "<scr!ipt>"
	 *       would bypass a check for "<script>" but a later step which then
	 *       removes the exclamation character would then enable the payload
	 *       as "<script">
	 * 
	 * REF: CMU Software Engineering Institute IDS11-J
	 * 
	 * @param str
	 * @return String
	 */
	public String validateString(String str) throws AppException {
		String s = Normalizer.normalize(str, Form.NFKC);
		
		/**
		 * SOLUTION: remove non-characters at this point before sanization
		 */
		String cleanStr = s.replaceAll("[\\p{Cn}]", "");
		
	    // Simple pattern match to remove <script> tag
	    Pattern pattern = Pattern.compile("<script>");
	    Matcher matcher = pattern.matcher(cleanStr);
	    
	    if (matcher.find()) {
	      throw new AppException("validateString() identified script tag", "Invalid input");
	    }
	 
	    /**
	     * SOLUTION: remove any unknown character before performing sanitization
	     */
	    // Deletes noncharacter code points
	    //String cleanStr = s.replaceAll("[\\p{Cn}]", "");
	    
		return cleanStr;
	}
	
	
	/**
	 * Project 1, Milestone 1, Task 4
	 * 
	 * TITLE: Sanitize data used in regular expressions
	 * 
	 * RISK: An attacker can inject regex into parameters if they know
	 *       the data is inserted in a regex expression. This may lead to leaking
	 *       of sensitive data or bypassing security checks.
	 * 
	 * REF: CMU Software Engineering Institute IDS08-J
	 * 
	 * @param str
	 * @return boolean
	 */
	public boolean regularExpression(String search) {
		/*
		 * SOLUTION: Do not insert untrusted data directly into a regex. 
         *           Sanitize the data first by removing characters which could be interpreted
         *           in the regex
		 */
	    StringBuilder sb = new StringBuilder(search.length());
	    for (int i = 0; i < search.length(); ++i) {
	        char ch = search.charAt(i);
	        if (Character.isLetterOrDigit(ch) || ch == ' ' || ch == '\'') {
	            sb.append(ch);
	        }
	    }
	    
	    search = sb.toString();
	    //SOLUTION END
	    
	    // Sanitize search string
		String regex = "(.* password\\[\\w+\\] .*" + search + ".*)";
        Pattern searchPattern = Pattern.compile(regex);
        Matcher patternMatcher = searchPattern.matcher(regex);
        
        //return boolean result of the find() operation
        return patternMatcher.find();
	}
	
	
	/**
	 * Project 1, Milestone 1, Task 5
	 * 
	 * TITLE: International string attacks
	 * 
	 * RISK: Use locale when comparing strings for security checks to avoid attacks with
	 *       international characters.
	 * 
	 * ADDITIONAL: The error is in two places in this method
	 * 
	 * REF: CMU Software Engineering Institute STR02-J
	 * 
	 * @param str
	 * @return String
	 */
	public boolean internationalization(String str) throws AppException {
		
		/*
		 * SOLUTION: some calls to convert text have a method for using a locale which can be leveraged 
		 *           to avoid attacks with non-standard characters
		 */
		//check for a script tag
		//if (str.toLowerCase().contains("script")) {
		if (str.toLowerCase(Locale.ENGLISH).contains("script")) {
		    throw new AppException("internationalization() found script tag", "application error");
		}
	
		//get the operating system
		String os = System.getProperty("os.name");
		String fileName="/dev/null";
		
		//select the correct file based on the operating system
		if(os.contains("indows")) {
			fileName = "NUL";
		}
		else if(os.contains("inux") || os.contains("ac")) {
			fileName = "/dev/null";
		}
		
		//write the text to file
		try (PrintWriter writer = new PrintWriter(new FileWriter(fileName)) ) {
			/**
			 * SOLUTION: The printf method is another which has the capability to format text with a locale
			 *           Another example to avoid additional attack vectors.
			 */
			//writer.printf("Passed text: %s", str);
			writer.printf(Locale.ENGLISH, "Passed text: %s", str);
			// SOLUTION END
			
			return true;
		}
		catch (IOException ioe) {
			throw new AppException("IOException in internationaliation(): " + ioe.getMessage(), 
					"application error");
		}
	}
	
	
	/**
	 * Project 1, Milestone 1, Task 6
	 * 
	 * TITLE: Logging unsanitized input
	 * 
	 * RISK: A malicious user could inject multi-line text which could obfuscate
	         login or other errors and make them appear successful
	 * 
	 * ADDITIONAL: For bonus work, update the AppLogger class so developers do not have
		           to sanitize every log and it is done in the logging class
	 * 
	 * REF: CMU Software Engineering Institute IDS03-J
	 * 
	 * @param unsanitizedText
	 * @return String
	 */
	public void logUnsanitizedText(String unsanitizedText) {
		/**
		 * SOLUTION: An example for filtering out end of line characters and tabs
		 * 
		 * BONUS SOLUTION: Perform the sanitization of all text in the logger.AppLogger class
		 * 
		 */
		String sanitizedText = Normalizer.normalize(unsanitizedText, Form.NFKC);
		
		sanitizedText = sanitizedText.replaceAll("\\r\\n", "\n");
		sanitizedText = sanitizedText.replaceAll("\\r", "\n");
		sanitizedText = sanitizedText.replaceAll("\t", "\n");
		
		AppLogger.log("Error: " + sanitizedText);
		// SOLUTION END
		
		/**
		 * SOLUTION: The text needs to be sanitized before being sent to the log
		 */
		//AppLogger.log("Error: " + unsanitizedText);

	}
	
	
	/**
	 * Project 1, Milestone 1, Task 7
	 * 
	 * TITLE: Avoid regex bypasses 
	 * 
	 * RISK: Matching can be used to replace malicious text. If the matching uses a predictable
	 *       pattern, attackers can send data which anticipates the replacement. Think about how
	 *       the following data would look after the simple replace in the method below:
	 *       <SCRIscriptPT>
	 * 
	 * ADDITIONAL: Regex and pattern matching to fix injected text is very complicated to develop from
	 *             scratch when taking into account encoding, double encoding, internationalization, Unicode,
	 *             and many other attack types. The best suggestion is to use existing library such as:
	 *             OWASP Java Encoder (https://github.com/OWASP/owasp-java-encoder/)
	 *             
	 *             Understanding the attack is important especially when trying to perform pattern
	 *             matching for other purposes.
	 * 
	 * @param str
	 * @return String
	 */
	public String regexBypass(String str) {
		String cleanText = str.toLowerCase(Locale.ENGLISH);
		
		/**
		 * SOLUTION: In the original version, the code only used replace(), so the occurrence of 
		 *           "<SCRIscriptPT>" would remove the inner "script" and leave behind the outer
		 *           "<SCRIPT>"
		 *           The solution should include a loop to avoid this problem and also ignore case
		 *           
         * 
		 * This is not a complete solution for all possible methods of identifying malicious tags
		 * the goal of this task is to demonstrate the need for multiple iterations. The best solution
		 * would be to use an experience library to perfrom the task such as the OWASP Encopder:
		 * 
		 * import org.owasp.encoder.Encode;
         * ...
		 * cleanText = Encode.forHtml(str);
		 * ...
		 * 
		 */
		//loop until text is no longer found
		boolean sanitized = false;
		while(! sanitized) {
		    // Simple pattern match to find <script> tag
		    Pattern pattern = Pattern.compile("<script>");
		    Matcher matcher = pattern.matcher(cleanText);
		    
		    if (! matcher.find()) {
		    	sanitized = true;
		    }
		    else {
		    	//case insensitive replace
		    	cleanText.replaceAll("(?i)<script>", "");
		    }
		}
		// SOLUTION END
		
		/**
		 * SOLUTION: The replace() call here is insufficient to replace multi-level attacks
		 */
		//cleanText.replace("script","");
		


		return cleanText;
	}
	
	
	/**
	 * Project 1, Milestone 2, Task 1
	 * 
	 * TITLE: Avoid variable width encoding
	 * 
	 * RISK: Data built with variable width encoding could be used to overwhelm memory or other 
	 *       resources if the String is created before checking the size.
	 * 
	 * REF: CMU Software Engineering Institute STR00-J
	 * 
	 * @param str
	 * @return String
	 */
	public String variableWidthEncoding(String str) throws AppException {
		File readFile = new File(str);
		String readStr = new String();
		
		try (FileInputStream fios = new FileInputStream(readFile) ) {
			byte[] data = new byte[1024+1];
			int offset = 0;
			int bytesRead = 0;
			
			while ((bytesRead = fios.read(data, offset, data.length - offset)) != -1) {
				/**
				 * SOLUTION: The string is not created till all of the data is read
				 *           so comment out this section
				 * 
				 * readStr += new String(data, offset, bytesRead, "UTF-8");
				 */
				
			    offset += bytesRead;
			    if (offset >= data.length) {
			    	throw new IOException("Too much input");
			    }
			}
			
			/**
			 * SOLUTION: Now build the string from the data after all of the data is read
			 */
			readStr = new String(data, 0, offset, "UTF-8");
			// SOLUTION END
		}
		catch(IOException | SecurityException ex) {
			throw new AppException("Caught exception reading file: " + ex.getMessage(), "application error");
		}
		
		return readStr;
	}
	
	
	/**
	 * Project 1, Milestone 2, Task 2
	 * 
	 * TITLE: Check before encoding non-character data as a string
	 * 
	 * RISK: Assuming strings are portable and can be converted without validating may compromise binary
	 *       versions of object such as password, numerals, and more
	 * 
	 * ADDITIONAL: Validate bytes are strings before building a new String object
	 * 
	 * REF: CMU Software Engineering Institute STR03-J
	 * 
	 * @param str
	 * @return String
	 */
	public BigInteger encodeNonCharacter(String base64Str) {
		//decode base64 to String representation of BigInt
		byte[] decodedBytes = Base64.getDecoder().decode(base64Str);
		
		/**
		 * SOLUTION: Before assuming the decoded text is a string, you should use
		 *           toString() to generate a string representation of the data
		 *           and then pass it to new String()
		 *           
		 * //convert bytes to string
		 * String s = new String(decodedBytes);
		 * byte[] byteArray = s.getBytes();
		 */
		String safeString = decodedBytes.toString();
		byte[] byteArray = safeString.getBytes();
		// SOLUTION END
		
		//convert string bytes to BigInt
		return new BigInteger(byteArray);
	}
	
	
	/**
	 * Project 1, Milestone 2,  Task 3
	 * 
	 * TITLE: Double encoding attacks
	 * 
	 * RISK: Attackers can encode HTML and JavaScript tags with hexadecimal or other format which
	 *       can bypass simple checks but will later be interpreted by the browser.
	 * 
	 * ADDITIONAL: An example double encoding for the traditional XSS attack of
	 * <script>alert('XSS')</script>
	 * 
	 * can be encoded as:
	 * %253Cscript%253Ealert('XSS')%253C%252Fscript%253E
	 * 
	 * REF: A few references to read
	 * - https://owasp.org/www-community/Double_Encoding
	 * - https://github.com/OWASP/owasp-java-encoder/
	 * - https://www.acunetix.com/blog/web-security-zone/xss-filter-evasion-basics/
	 * 
	 * @param str
	 * @return String
	 */
	public String doubleEncoding(String str) {
		/**
		 * SOLUTION: We will not use the matcher() and find() to look for malicious characters
		 *           We will comment out all of the previous code and use another library.
		 */
		
		/**
		Pattern pattern = Pattern.compile("[<&>]");
		Matcher matcher = pattern.matcher(str);
		
		String cleanStr = str;
	
		//variable str is potentially dirty with HTML or JavaScript tags so remove left, right, or amp
		if (matcher.find()) {
			cleanStr = str.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">", "&gt;");
		}
		**/
		
		
		/**
		 * SOLUTION: Manually detecting and fixing encoding attacks is very difficult, so we can use
		 *           a third-party solution. The OWASP Java Encoder has many methods for protecting
		 *           input and output.
		 *           
		 *           Use the Enocde() library to prepare the untrusted text
		 *           
		 *           Above we need to import org.owasp.encoder.Encode;
		 */
		String cleanStr = Encode.forHtml(str);
		//SOLUTION END
		
		return cleanStr;
	}
	

	/**
	 * Project 1, Milestone 2,  Task 4
	 * 
	 * TITLE: Handling encoding on file streams
	 * 
	 * RISK: The JVM converts encoding differently based on many options, so a malicious user could exploit this
	 *       to put file operations into an unexpected state. File operations must explicitly define the character
	 *       encoding.
	 * 
	 * REF: CMU Software Engineering Institute STR04-J
	 * 
	 * @param str
	 * @return String
	 */
	public String fileEncoding(String fileName) throws AppException {
		try (FileInputStream fis = new FileInputStream(fileName)) {
			DataInputStream dis = new DataInputStream(fis);
			byte[] data = new byte[1024];
			dis.readFully(data);
			
			/**
			 * SOLUTION: The new String() call did not explicitly define the string encoding so we will comment
			 *           it out and provide an explicit definition to UTF-16LE
			 *
			 *
			 * return new String(data);
			 */
			 
			return new String(data, "UTF-16LE");
			//SOLUTION END
		} 
		catch (IOException ioe) {
			throw new AppException("fileEncoding caused exception: " + ioe.getMessage(), "Application error");
		} 
	}

	
	/**
	 * Project 1, Milestone 3, Task 1
	 * 
	 * Preventing Integer overflow
	 * CMU Software Engineering Institute NUM00-J
	 * 
	 * @param num
	 * @return Integer
	 */
	public Integer task13(Integer num) {
		//TODO
		return num;
	}
	
	
	/**
	 * Project 1 - Task 14
	 * 
	 * Divide by zero errors
	 * CMU Software Engineering Institute NUM02-J
	 * 
	 * @param int
	 * @return Integer
	 */
	public Integer task14(Integer num) {
		//TODO
		return num;
	}
	
	
	/**
	 * Project 1 - Task 15
	 * 
	 * Avoid NaN calculations
	 * CMU Software Engineering Institute NUM07-J and NUM08-J
	 * 
	 * @param num
	 * @return Integer
	 */
	public String task15(String str) {
		//TODO
		return str;
	}
	
	
	/**
	 * Project 1 - Task 16
	 * 
	 * String representation of numbers
	 * CMU Software Engineering Institute NUM11-J
	 * 
	 * @param num
	 * @return Integer
	 */
	public String task16(String str) {
		//TODO
		return str;
	}
	
	
}
