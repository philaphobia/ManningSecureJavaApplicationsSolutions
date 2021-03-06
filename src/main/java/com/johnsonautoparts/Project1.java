package com.johnsonautoparts;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.*;
import java.util.regex.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.encoder.Encode; //SOLUTION: added for Milestone 2, Task 3, Method doubleEncoding()

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

import com.johnsonautoparts.exception.AppException;
import com.johnsonautoparts.logger.AppLogger;

/*
 * 
 * SOLUTIONS INCLUDED FOR ALL MILESTONES AND TASKS
 * 
 * Project1 class which contains all the method for the milestones. The task
 * number represents the steps within a milestone.
 * 
 * Each method has a name which denotes the type of security check we will be
 * fixing. There are several fields in the notes of each method:
 * 
 * TITLE - this is a description of code we are trying to fix RISK - Some
 * explanation of the security risk we are trying to avoid ADDITIONAL - Further
 * help or explanation about work to try REF - An ID to an external reference
 * which is used in the help of the liveProject
 * 
 */
public class Project1 extends Project {

	public Project1(Connection connection, HttpServletRequest httpRequest,
			HttpServletResponse httpResponse) {
		super(connection, httpRequest, httpResponse);
	}

	/*
	 * Project 1, Milestone 1, Task 1
	 * 
	 * TITLE: Normalize strings before validation
	 * 
	 * RISK: Since the text is not normalized, the cleaning step may not fix any
	 * injections of invalid characters
	 * 
	 * REF: CMU Software Engineering Institute IDS01-J
	 * 
	 * @param str
	 * @return String
	 */
	public String normalizeString(String str) {
		Pattern pattern = Pattern.compile("[<&>]");
		Matcher matcher = pattern.matcher(str);

		/*
		 * SOLUTION: normalize the string before performing check to remove
		 * Unicode which can be used as an attack vector
		 */
		String cleanStr = Normalizer.normalize(str, Form.NFKC);

		// variable str is potentially dirty with HTML or JavaScript tags
		if (matcher.find()) {
			cleanStr = str.replaceAll("&", "&amp;").replaceAll("<", "&lt;")
					.replaceAll(">", "&gt;");
		}

		/*
		 * SOLUTION: move this before the pattern matching since normalize()
		 * needs to
		 */
		// cleanStr = Normalizer.normalize(cleanStr, Form.NFKC);
		return cleanStr;
	}

	/*
	 * Project 1, Milestone 1, Task 2
	 * 
	 * TITLE: Avoid leaking data with Format string
	 * 
	 * RISK: Attackers could inject formatting strings into variable which the
	 * application will process and leak
	 * 
	 * REF: CMU Software Engineering Institute IDS06-J
	 * 
	 * @param str
	 * @return String
	 */
	public String formatString(String str) throws IllegalStateException {
		Calendar cal = new GregorianCalendar();

		/*
		 * SOLUTION: Do not use untrusted input in the format string. Use The
		 * format pattern to rend the untrusted content as a string
		 */
		// return String.format(str + " passed on date %tF", cal);
		return String.format("%s passed on date %tF", str, cal);
	}

	/*
	 * Project 1, Milestone 1, Task 3
	 * 
	 * TITLE: String modification before validation
	 * 
	 * RISK: An attacker may use Unicode or other special characters which will
	 * help bypass filters, but are then removed later and the attack succeeds.
	 * For example, text passed as "<scr!ipt>" would bypass a check for
	 * "<script>" but a later step which then removes the exclamation character
	 * would then enable the payload as "<script">
	 * 
	 * REF: CMU Software Engineering Institute IDS11-J
	 * 
	 * @param str
	 * @return String
	 */
	public String validateString(String str) throws AppException {
		String s = Normalizer.normalize(str, Form.NFKC);

		/*
		 * SOLUTION: remove non-characters at this point before sanitization
		 */
		//String cleanStr = s.replaceAll("[\\p{Cn}]", "");
		String cleanStr =  s.replaceAll("!", "");

		// Simple pattern match to remove <script> tag
		Pattern pattern = Pattern.compile("<script>");
		Matcher matcher = pattern.matcher(cleanStr);

		if (matcher.find()) {
			throw new AppException("validateString() identified script tag",
					"Invalid input");
		}

		/*
		 * SOLUTION: remove any unknown character before performing sanitization
		 */
		// Deletes noncharacter code points
		// return s.replaceAll("!", "");

		return cleanStr;
	}

	/*
	 * Project 1, Milestone 1, Task 4
	 * 
	 * TITLE: Sanitize data used in regular expressions
	 * 
	 * RISK: An attacker can inject regex into parameters if they know the data
	 * is inserted in a regex expression. This may lead to leaking of sensitive
	 * data or bypassing security checks.
	 * 
	 * The following method allows users to search errorr marked as public
	 * but not filtering out regex could allow a malicious user to bypass the
	 * filter if their search was ".*)|(.*
	 *
	 * REF: CMU Software Engineering Institute IDS08-J
	 * 
	 * @param search
	 * @return boolean
	 */
	public String searchErrorMessage(String search) {
		/*
		 * SOLUTION: Do not insert untrusted data directly into a regex.
		 * Sanitize the data first by removing characters which could be
		 * interpreted in the regex
		 *
		 * In the following sample solution, a regex is used to match
		 * all characters which are letters and number and replace those
		 * with empty
		 */
		search = search.replaceAll("[^a-zA-Z0-9]", "");
		// SOLUTION END

		// Sanitize search string
		String regex = ".* public user: \\w+ message: .*(" + search + ".*)";
		Pattern searchPattern = Pattern.compile(regex);

		// retrieve the error even from the session
		HttpSession session = httpRequest.getSession();

		// make sure data was retrieved from the attribute
		Object errorEventObject = session.getAttribute("error_event");
		if (errorEventObject == null) {
			return null;
		}

		// make sure the content is a String before comparing
		if (errorEventObject instanceof String) {
			Matcher patternMatcher = searchPattern
					.matcher(errorEventObject.toString());

			// return the matching text
			if (patternMatcher.find() ) {
				return patternMatcher.group(0);
			} else {
				return null;
			}

		} else {
			return null;
		}
	}

	/*
	 * Project 1, Milestone 1, Task 5
	 * 
	 * TITLE: International string attacks
	 * 
	 * RISK: Use locale when comparing strings for security checks to avoid
	 * attacks with international characters.
	 * 
	 * ADDITIONAL: The error is in two places in this method
	 * 
	 * REF: CMU Software Engineering Institute STR02-J
	 * 
	 * @param str
	 * @return boolean
	 */
	public boolean internationalization(String str) throws AppException {

		/*
		 * SOLUTION: some calls to convert text have a method for using a locale
		 * which can be leveraged to avoid attacks with non-standard characters
		 */
		// check for a script tag
		// if (str.toLowerCase().contains("script")) {
		if (str.toLowerCase(Locale.ENGLISH).contains("script")) {
			throw new AppException("internationalization() found script tag");
		}

		// create a temp file
		Path tempFile = null;
		try {
			tempFile = Files.createTempFile("", ".tmp");
		} catch (IOException ioe) {
			throw new AppException("IOException in internationalization(): "
					+ ioe.getMessage());
		}

		// write the text to file
		try (PrintWriter writer = new PrintWriter(
				new FileWriter(tempFile.toFile()))) {
			/*
			 * SOLUTION: The printf method is another which has the capability
			 * to format text with a locale Another example to avoid additional
			 * attack vectors.
			 */
			// writer.printf("Passed text: %s", str);
			writer.printf(Locale.ENGLISH, "Passed text: %s", str);
			// SOLUTION END

			return true;
		} catch (IOException ioe) {
			throw new AppException("IOException in internationalization(): "
					+ ioe.getMessage());
		}
	}

	/*
	 * Project 1, Milestone 1, Task 6
	 * 
	 * TITLE: Logging unsanitized input
	 * 
	 * RISK: A malicious user could inject multi-line text which could obfuscate
	 * login or other errors and make them appear successful
	 * 
	 * ADDITIONAL: For bonus work, update the AppLogger class so developers do
	 * not have to sanitize every log and it is done in the logging class
	 * 
	 * REF: CMU Software Engineering Institute IDS03-J
	 * 
	 * @param unsanitizedText
	 * @return String
	 */
	public void logUnsanitizedText(String unsanitizedText) {
		/*
		 * SOLUTION: An example for filtering out end of line characters and
		 * tabs
		 * 
		 * BONUS SOLUTION: Perform the sanitization of all text in the
		 * logger.AppLogger class
		 */
		String sanitizedText = Normalizer.normalize(unsanitizedText, Form.NFKC);

		sanitizedText = sanitizedText.replaceAll("[\n|\r|\t]", "_");

		AppLogger.log("Error: " + sanitizedText);
		// SOLUTION END

		/*
		 * SOLUTION: The text needs to be sanitized before being sent to the log
		 */
		// AppLogger.log("Error: " + unsanitizedText);

	}

	/*
	 * Project 1, Milestone 1, Task 7
	 * 
	 * TITLE: Avoid regex bypasses
	 * 
	 * RISK: Matching can be used to replace malicious text. If the matching
	 * uses a predictable pattern, attackers can send data which anticipates the
	 * replacement. Think about how the following data would look after the
	 * simple replace in the method below: <SCRIscriptPT>
	 * 
	 * ADDITIONAL: Regex and pattern matching to fix injected text is very
	 * complicated to develop from scratch when taking into account encoding,
	 * double encoding, internationalization, Unicode, and many other attack
	 * types. The best suggestion is to use existing library such as: OWASP Java
	 * Encoder (https://github.com/OWASP/owasp-java-encoder/)
	 * 
	 * The OWASP Java Encoder project contains several methods to protect the data
	 * encoding. For this task, we want to encode the data to HTML.
	 * 
	 * Understanding the attack is important especially when trying to perform
	 * pattern matching for other purposes.
	 * 
	 * @param str
	 * @return String
	 */
	public String regexClean(String str) {
		String cleanText = str.toLowerCase(Locale.ENGLISH);

		/*
		 * SOLUTION: In the original version, the code only used replace(), so
		 * the occurrence of "<SCRIscriptPT>" would remove the inner "script"
		 * and leave behind the outer "<SCRIPT>" The solution should include a
		 * loop to avoid this problem and also ignore case
		 * 
		 * 
		 * This is not a complete solution for all possible methods of
		 * identifying malicious tags the goal of this task is to demonstrate
		 * the need for multiple iterations. The best solution would be to use
		 * an experience library to perform the task such as the OWASP Encopder:
		 * 
		 * import org.owasp.encoder.Encode; ... cleanText = Encode.forHtml(str);
		 * ...
		 * 
		 */
		// loop until text is no longer found
		boolean sanitized = false;
		while (!sanitized) {
			// Simple pattern match to find <script> tag
			Pattern pattern = Pattern.compile("<script>");
			Matcher matcher = pattern.matcher(cleanText);

			if (!matcher.find()) {
				sanitized = true;
			} else {
				// case insensitive replace
				cleanText = cleanText.replaceAll("(?i)<script>", "");
			}
		}
		// SOLUTION END

		/*
		 * SOLUTION: The replace() call here is insufficient to replace
		 * multi-level attacks
		 */
		// cleanText.replace("script","");

		return cleanText;
	}

	/*
	 * Project 1, Milestone 2, Task 1
	 * 
	 * TITLE: Avoid variable width encoding
	 * 
	 * RISK: Data built with variable width encoding could be used to overwhelm
	 * memory or other resources if the String is created before checking the
	 * size.
	 * 
	 * REF: CMU Software Engineering Institute STR00-J
	 * 
	 * @param str
	 * @return String
	 */
	public String readFile(String str) throws AppException {
		final int MAX_READ_SIZE = 1024;
		
		Path path = null;
		try {
			path = Paths.get(str);
		} catch (InvalidPathException ipe) {
			throw new AppException(
					"variableWidthEncoding was given and invalid path");
		}

		try (FileInputStream fios = new FileInputStream(path.toString())) {
			byte[] data = new byte[MAX_READ_SIZE + 1];
			int offset = 0;
			int bytesRead = 0;

			while ((bytesRead = fios.read(data, offset,
					data.length - offset)) != -1) {
				/*
				 * SOLUTION: The string is not created till all of the data is
				 * read so comment out this section
				 * 
				 * readStr += new String(data, offset, bytesRead, "UTF-8");
				 */

				offset += bytesRead;
				if (offset >= data.length) {
					throw new IOException("Too much input");
				}
			}

			/*
			 * SOLUTION: Now build the string from the data after all of the
			 * data is read and also define the characterset
			 */
			return new String(data, 0, offset, StandardCharsets.UTF_8);
			// SOLUTION END
		} catch (IOException ioe) {
			throw new AppException(
					"Caught exception reading file: " + ioe.getMessage());
		}

	}

	/*
	 * Project 1, Milestone 2, Task 2
	 * 
	 * TITLE: Check before encoding non-character data as a string
	 * 
	 * RISK: Assuming strings are portable and can be converted without
	 * validating may compromise binary versions of object such as password,
	 * numerals, and more
	 * 
	 * ADDITIONAL: Validate bytes are strings before building a new String
	 * object
	 * 
	 * REF: CMU Software Engineering Institute STR03-J
	 * 
	 * @param base64Str
	 * @return BigInteger
	 */
	public BigInteger decodeBase64(String base64Str) {
		// decode base64 to String representation of BigInt
		byte[] decodedBytes = Base64.getDecoder().decode(base64Str);

		/*
		 * SOLUTION: Before assuming the decoded text is a string, you should
		 * use toString() to generate a string representation of the data and
		 * then pass it to new String(). The method getBytes() should also
		 * define a specific characterset
		 * 
		 * //convert bytes to string String s = new String(decodedBytes); byte[]
		 * byteArray = s.getBytes();
		 */
		String safeString = Arrays.toString(decodedBytes);
		byte[] byteArray = safeString.getBytes(StandardCharsets.UTF_8);
		// SOLUTION END

		/*
		 * SOLUTION: Hint for a later milestone, but this direct instantiation
		 * of BigInteger() did not perform any check on the size of the numeric
		 * representation of the string. It is also not catching
		 * NumberFormatException which could be thrown here. These errors can be
		 * fixed for extra credit
		 */
		// convert string bytes to BigInt
		return new BigInteger(byteArray);
	}

	/*
	 * Project 1, Milestone 2, Task 3
	 * 
	 * TITLE: Double encoding attacks
	 * 
	 * RISK: Attackers can encode HTML and JavaScript tags with hexadecimal or
	 * other format which can bypass simple checks but will later be interpreted
	 * by the browser.
	 * 
	 * ADDITIONAL: An example double encoding for the traditional XSS attack of
	 * <script>alert('XSS')</script>
	 * 
	 * can be encoded as: %253Cscript%253Ealert('XSS')%253C%252Fscript%253E
	 * 
	 * REF: A few references to read -
	 * https://owasp.org/www-community/Double_Encoding -
	 * https://github.com/OWASP/owasp-java-encoder/ -
	 * https://www.acunetix.com/blog/web-security-zone/xss-filter-evasion-basics/
	 * 
	 * @param str
	 * @return String
	 */
	public String cleanBadHTMLTags(String str) {
		/*
		 * SOLUTION: We will not use the matcher() and find() to look for
		 * malicious characters We will comment out all of the previous code and
		 * use another library.
		 */

		/*
		 * Pattern pattern = Pattern.compile("[<&>]"); Matcher matcher =
		 * pattern.matcher(str);
		 * 
		 * String cleanStr = str;
		 * 
		 * //variable str is potentially dirty with HTML or JavaScript tags so
		 * remove left, right, or amp if (matcher.find()) { cleanStr =
		 * str.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">",
		 * "&gt;"); }
		 **/

		/*
		 * SOLUTION: Manually detecting and fixing encoding attacks is very
		 * difficult, so we can use a third-party solution. The OWASP Java
		 * Encoder has many methods for protecting input and output.
		 * 
		 * Use the Encode() library to prepare the untrusted text
		 * 
		 * At the top of the Class we need to import org.owasp.encoder.Encode;
		 */
		String cleanStr = Encode.forHtml(str);
		// SOLUTION END

		return cleanStr;
	}

	/*
	 * Project 1, Milestone 2, Task 4
	 * 
	 * TITLE: Handling encoding on file streams
	 * 
	 * RISK: The JVM converts encoding differently based on many options, so a
	 * malicious user could exploit this to put file operations into an
	 * unexpected state. File operations must explicitly define the character
	 * encoding.
	 * 
	 * REF: CMU Software Engineering Institute STR04-J
	 * 
	 * @param fileName
	 * @return String
	 */
	public String getFileContents(String fileName) throws AppException {
		try (FileInputStream fis = new FileInputStream(fileName)) {
			try (DataInputStream dis = new DataInputStream(fis)) {
				byte[] data = new byte[1024];
				dis.readFully(data);

				/*
				 * SOLUTION: The new String() call did not explicitly define the
				 * string encoding so we will comment it out and provide an
				 * explicit definition to UTF-16LE
				 *
				 * return new String(data);
				 */

				return new String(data, StandardCharsets.UTF_16);
				// SOLUTION END
			}
		} catch (IOException ioe) {
			throw new AppException(
					"fileEncoding caused exception: " + ioe.getMessage());
		}
	}

	/*
	 * Project 1, Milestone 3, Task 1
	 * 
	 * TITLE: Preventing Integer overflow
	 * 
	 * RISK: Integer overflow can occur with add, subtract, multiply, divide,
	 * and other mathematical operations. We will cover a few here to provide
	 * the foundation for understanding.
	 * 
	 * REF: CMU Software Engineering Institute NUM00-J
	 * 
	 * @param num
	 * @return int
	 */
	public int calcTotalValue(int num) throws AppException {
		int multiplier = 2;
		int addedCost = 12;

		/*
		 * SOLUTION: Java 8 added new mathematical features to avoid integer
		 * overflow Math.addExact() and Math.multiplyExact(). These methods
		 * should be used instead of basic math operators.
		 *
		 * The existing code was commented out and replaced with the new Math
		 * methods. The following import is also need to catch the overflow.
		 * 
		 * import java.math.ArithmeticException;
		 * 
		 * int addCost = num + addedCost; int multiCost = num * multiplier;
		 *
		 */
		try {
			int addCost = Math.addExact(num, addedCost);
			int multiCost = Math.multiplyExact(num, multiplier);

			if (addCost > multiCost) {
				return addCost;
			} else {
				return multiCost;
			}
		} catch (ArithmeticException ae) {
			throw new AppException("calcTotalValue caught ArithmeticException: "
					+ ae.getMessage());
		}
		// SOLUTION END

	}

	/*
	 * Project 1, Milestone 3, Task 2
	 * 
	 * TITLE: Divide by zero errors
	 * 
	 * RISK: If the application performs a divide by zero in the operation, it
	 * could cause the application to fail into an unknown state or crash. A
	 * malicious user to create a denial of service attack with a simple to
	 * perform malicious input.
	 * 
	 * REF: CMU Software Engineering Institute NUM02-J
	 * 
	 * @param monthlyTasks
	 * @return int
	 */
	public int divideTask(int monthlyTasks) throws AppException {
		int monthly = 12;

		/*
		 * SOLUTION: Need to check if the param monthlyTasks is zero before
		 * performing math
		 * 
		 * Use an if statement to check for zero and throw an error if needed
		 * 
		 * The solution also requires adding a throw to the method if zero is
		 * detected
		 */
		if (monthlyTasks == 0) {
			throw new AppException(
					"monthlyTasks caught exception with zero passed");
		}
		// SOLUTION END

		return monthly / monthlyTasks;
	}

	/*
	 * Project 1, Milestone 3, Task 3
	 * 
	 * TITLE: Avoid calculations on NaN and infinity
	 * 
	 * RISK: The equality check to NaN does not always produce expected results,
	 * which could place the check into an unknown state. This could allow a
	 * malicious attacker to cause instability, denial of service, or possibly
	 * bypass checks. The method also fails to account for the userInput value
	 * being other values such as infinity or -infinity.
	 * 
	 * REF: CMU Software Engineering Institute NUM07-J and NUM08-J
	 * 
	 * @param num
	 * @return boolean
	 */
	public boolean comparisonTask(String num) throws AppException {
		double compareTaskId = 6.1;

		try {
			double userInput = Double.parseDouble(num);

			double result = Math.cos(compareTaskId / userInput); // Returns NaN if
															// input is infinity

			/*
			 * SOLUTION: The comparison to Double.NaN will always return false
			 * which is not the expected result
			 * 
			 * The comparison should be performed instead with Double.isNaN() In
			 * addition, the number should also be validated as not infinity
			 * with Double.isInfinite()
			 * 
			 * The original check is commented out
			 *
			 * //check if we received the expected result return (result == Double.NaN) {
			 *
			 */
			if (Double.isNaN(result)) {
				return false;
			} else if (Double.isInfinite(result)) {
				return false;
			}
			// SOLUTION END

			else {
				return true;
			}
		} catch (NumberFormatException nfe) {
			throw new AppException(
					"comparisonTask caught number exception from user input: "
							+ nfe.getMessage());
		}
	}

	/*
	 * Project 1, Milestone 3, Task 4
	 * 
	 * TITLE: String representation of numbers
	 * 
	 * RISK: String representations of numbers can return unexpected results
	 * based on the precision or other other factors such as scientific
	 * notation. Attempting to compare the string representation is not a secure
	 * method and can lead to unexpected results or bypasses of checks.
	 * 
	 * REF: CMU Software Engineering Institute NUM11-J
	 * 
	 * @param num
	 * @return boolean
	 */
	public boolean numStringCompare(int num) {
		/*
		 * SOLUTION: String comparison of numeric data is not recommended, but
		 * if it is required you can use BigDecimal to avoid precision loss
		 * before performing the comparison
		 * 
		 * The entire code from the original is commented out and replace with
		 * the BigDecimal comparison method
		 *
		 * String s = Double.valueOf(num / 1000.0).toString();
		 *
		 * //check for comparison to validate if (s.equals("0.001")) { return
		 * true; } //string data may be in a slightly different format so
		 * perform additional //check if we can match by removing any trailing
		 * zeroes else { s = s.replaceFirst("[.0]*$", ""); if
		 * (s.equals("0.001")) { return true; } //neither check matched so
		 * return false else { return false; } }
		 */
		BigDecimal d = new BigDecimal(Double.valueOf(num / 1000.0).toString());

		return (d.compareTo(new BigDecimal("0.001")) == 0);
		// SOLUTION END
	}

	/*
	 * Project 1, Milestone 3, Task 5
	 * 
	 * TITLE: Generate strong random number
	 * 
	 * RISK: Easy to predict numbers from weak pseudo random number generators
	 * could be exploited by malicious actors.
	 * 
	 * REF: CMU Software Engineering Institute MSC02-J
	 * 
	 * @param range
	 * @return boolean
	 */
	public int randomNumGenerate(int range) throws AppException {
		/*
		 * SOLUTION: The Random class does not produce strong random number
		 * generation and developers should use SecureRandom instead.
		 * SecureRandom requires the import below. In addition, Java 8 provides
		 * strong instances which requires the import of
		 * NoSuchAlgorithmException
		 * 
		 * import java.security.SecureRandom; import
		 * java.security.NoSuchAlgorithmException;
		 *
		 * //seed the random number generator Random number = new Random(99L);
		 * 
		 * return number.nextInt(range);
		 */
		try {
			SecureRandom number = SecureRandom.getInstanceStrong();

			// generate a random number based on the range given
			return number.nextInt(range);
		} catch (NoSuchAlgorithmException nsae) {
			throw new AppException(
					"randomNumGenerate caught NoSuchAlgorithmException: "
							+ nsae.getMessage());
		}
		// SOLUTION END
	}

}
