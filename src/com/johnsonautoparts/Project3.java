package com.johnsonautoparts;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.johnsonautoparts.Project3.CheckSession;
import com.johnsonautoparts.exception.AppException;
import com.johnsonautoparts.logger.AppLogger;
import com.johnsonautoparts.servlet.SessionConstant;

/**
 * Project3 class which contains all the method for the milestones. The task number represents the
 * steps within a milestone.
 *
 * <p>Each method has a name which denotes the type of security check we will be fixing. There are
 * several fields in the notes of each method:
 *
 * <p>TITLE - this is a description of code we are trying to fix RISK - Some explanation of the
 * security risk we are trying to avoid ADDITIONAL - Further help or explanation about work to try
 * REF - An ID to an external reference which is used in the help of the liveProject
 */
public class Project3 extends Project {

  public Project3(
      Connection connection, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
    super(connection, httpRequest, httpResponse);
  }

  /**
   * Project 3, Milestone 1, Task 1
   *
   * <p>TITLE: Suppressing exceptions
   *
   * <p>RISK: Developers sometimes catch exceptions and only print the stack or simply ignore. A
   * program can become unstable if execution is allowed to pass an unexpected state. Malicious
   * users could also leverage the logic error to bypass controls.
   *
   * <p>REF: CMU Software Engineering Institute ERR00-J
   *
   * @param query
   * @return String
   */
  public boolean suppressException(String str) throws AppException {
    // try to authenticate the user
    try {
      httpRequest.authenticate(httpResponse);
      /**
       * SOLUTION: The return of true should be here within the try block to avoid program flow
       * outside of the exceptions.
       */
      return true;
      // SOLUTION END
    } catch (IOException ioe) {
      /**
       * SOLUTION: While the exception was caught, neither the printStackTrace() nor the AppLogger
       * will stop execution flow inside the method. The program will continue outside of the
       * try-catch block and return true, which is incorrect
       *
       * <p>The following lines are commented out and replace with a throw exception to stop
       * execution flow.
       *
       * <p>ioe.printStackTrace(); AppLogger.log("login IO error: " + ioe.getMessage());
       */
      throw new AppException("login caused IO exception: " + ioe.getMessage());
      // SOLUTION END
    } catch (ServletException se) {
      throw new AppException("login exception: " + se.getMessage());
    }

    /**
     * SOLUTION: Once the above errors were fixed, then this code is no longer reachable and
     * commented out
     *
     * <p>//reached this far so return true return true;
     */
    // SOLUTION END
  }

  /**
   * Project 3, Milestone 1, Task 2
   *
   * <p>TITLE: Sensitive data exposure from exceptions
   *
   * <p>RISK: Returning sensitive data to a user can allow for malicious discovery of files on the
   * file system. With direct feedback, a malicious user could continue to try different
   * combinations to find sensitive data.
   *
   * <p>REF: CMU Software Engineering Institute ERR01-J
   *
   * @param filePath
   * @return String contents of the file only
   */
  public String dataExposure(String filePath) throws AppException {
    try {
      Path path = Paths.get(filePath);

      StringBuilder sb = new StringBuilder();

      // read the data stream of the file into string
      try (Stream<String> stream = Files.lines(path)) {
        stream.forEach(s -> sb.append(s).append("\n"));

        return sb.toString();
      } catch (IOException ex) {
        /*
         * SOLUTION: The exception is caught correctly but the sensitive data in the error
         *           is returned to the user. You should send a generic error. You can do
         *           that here or use the existing AppException() which provides the ability
         *           to log the technical data and also send a generic error.
         *
         *           The line is commented out here
         *
         * return("Error reading file: " + ex.getMessage());
         */
        throw new AppException("Error reading file: " + ex.getMessage());
        // SOLUTION END
      }
    } catch (InvalidPathException ipe) {
      /*
       * SOLUTION: Same error as describe above.
       *
       *           The line is commented out and replaced with AppException
       *
       * return("Error with requested file: " + ipe.getMessage());
       */
      throw new AppException("Error with requested file: " + ipe.getMessage());
    }
  }

  /**
   * Project 3, Milestone 1, Task 3
   *
   * <p>TITLE: Exceptions during logging
   *
   * <p>RISK: Logging information to uncontrolled streams cannot guarantee that the audit data is
   * successfully captured. Malicious activity could be concealed or lost if it is not logged in a
   * guaranteed manner.
   *
   * <p>REF: CMU Software Engineering Institute ERR02-J
   *
   * @param userData
   * @return String
   */
  public String exceptionLogging(String userData) throws AppException {
    // get session data
    try {
      HttpSession session = httpRequest.getSession();
      Object userDataObj = session.getAttribute(userData);

      // check if userData was retrieved
      if (userDataObj == null) {
        throw new IllegalStateException("userData is null");
      }

      // return the data
      if (userDataObj instanceof String) {
        return (String) userDataObj;
      } else {
        /*
         * SOLUTION: Auditing security errors to standard output stream may not guarantee
         *           the log reaches the correct destination. Also, in the current case
         *           the method logic does not follow by returning a null. If no data exists,
         *           an exception should be throw to follow the same pattern as the userData
         *           is null above.
         *
         *           The following lines are commented out and replace with an exception.
         *
         * System.err.println("no user data in session");
         * return null;
         */
        throw new IllegalStateException("user_data is not the expected String object");
        // SOLUTION END
      }
    } catch (IllegalStateException se) {
      /*
       * SOLUTION: As above, stdout and stderr are not guaranteed and may be sent to a different
       *           log than the standard logger. An exception should be thrown to stop execution
       *           flow.
       *
       *           The following line is commented out:
       *
       * System.err.println("getSession() caused IllegalState: " + se.getMessage());
       */
      throw new AppException("exceptionLogging caught illegal state: " + se.getMessage());
      // SOLUTION END
    }

    /*
     * SOLUTION: With the execution flow fixed above, the logic error has been resolved and the
     *           code below is no longer reachable.
     *
     *           The lines are commented out.
     *
     * //not sure how this point was reached so return null and let the calling function handle
     * return null;
     */
  }

  /**
   * Project 3, Milestone 2, Task 1
   *
   * <p>TITLE: Restore object state on failure
   *
   * <p>RISK: Upon failure, the state of a object should be returned to the previous state or the
   * data can become out of sync. Malicious users can leverage the logic error to bypass controls or
   * perform a denial of service.
   *
   * <p>ADDITONAL: The method retrieves the contents of a PDF file in the database accessed by the
   * ID passed to the method. The method keeps track of the number of documents accessed during the
   * existing session. This is done by retrieving the value of the session attribute
   * "docs_accessed". Each time a document is accessed, the value of "docs_accessed" is incremented.
   *
   * <p>REF: CMU Software Engineering Institute ERR03-J
   *
   * @param pdfId
   * @return String
   */
  public String restoreState(String pdfId) throws AppException {
    HttpSession session = httpRequest.getSession();
    Object accessedObj = session.getAttribute(SessionConstant.DOCS_ACCESSED);

    // track number of docs accessed in session
    int accessed = 0;

    // update if it existing or leave as zero
    if (accessedObj instanceof Integer) {
      accessed = (Integer) accessedObj;
    }

    /*
     * SOLUTION: The line below is the error in the code. The docs_accessed attribute
     *           is updated before the DB commands complete successfully. If the attribute
     *           is used to track licensing or other security features than this bug
     *           would present as a critical error.
     *
     *           There are multiple ways to fix the issue. The finally block could be used
     *           to roll back change or the attribute could be set after all commands have
     *           executed which could possible throw exceptions. For this example we will
     *           set the attribute increment after the SQL commands have executed.
     *
     *           The lines below are commented out.
     *
     * //increment the docs_accessed in the session attribute
     * session.setAttribute("docs_accessed", accessed + 1);
     */
    // SOLUTION END

    // get the content from the database
    try {
      String sql = "SELECT content FROM docs WHERE id = ?";
      try (PreparedStatement stmt = connection.prepareStatement(sql)) {

        // force the id into an integer by casting and catching any exceptions
        int id = 0;
        try {
          id = Integer.parseInt(pdfId);
        } catch (NumberFormatException nfe) {
          throw new AppException("restoreState failed to parse integer: " + nfe.getMessage());
        }

        // set the parameter and execute the SQL
        stmt.setInt(1, id);
        try (ResultSet rs = stmt.executeQuery()) {

          // return the count
          if (rs.next()) {
            /*
             * SOLUTION: The getString method could still throw an exception so we
             *           need to edit the code to retrieve the string before incrementing
             *           and then returning the data.
             *
             *           The return line is commented out below:
             *
             * return rs.getString(1);
             */
            String returnStr = rs.getString(1);
            if (returnStr == null) {
              throw new AppException("restoreState received null response from db");
            }

            /** SOLUTION: All execution has completed successfully so now set the state */
            session.setAttribute(SessionConstant.DOCS_ACCESSED, accessed + 1);

            // data is not null so return
            return (returnStr);
            // SOLLUTION END
          } else {
            throw new AppException("restoreState did not return any results");
          }
        } // end resultset
      } // end statement

    } catch (SQLException se) {
      throw new AppException("restoreState caught SQLException: " + se.getMessage());
    } finally {
      try {
        connection.close();
      } catch (SQLException se) {
        // this is an application error but does not represent an error for the user
        AppLogger.log("restoreState failed to close connection: " + se.getMessage());
      }
    }
  }

  /**
   * Project 3, Milestone 2, Task 2
   *
   * <p>TITLE: Exception handling flow
   *
   * <p>RISK: The finally clause should be used to clean up after an exception is caught but should
   * not end execution flow abruptly. The finally block should also not execute any methods which
   * could cause new exceptions to be thrown.
   *
   * <p>REF: CMU Software Engineering Institute ERR004-J, ERR05-J
   *
   * @param query
   * @return String
   */
  /*
   * SOLUTION: The first hint of a problem is the SuppressWarning here which should not be necessary
   *           if the code was developed correctly. Instead of throwing the catch-all generic
   *           Exception, the method should only throw a specific exception
   *
   *           The following lines are commented out:
   *
   * @SuppressWarnings({ "finally", "resource" })
   *
   * public boolean flowHandling(String fileContents) throws Exception {
   */
  // SOLUTION END
  public boolean flowHandling(String fileContents) throws AppException {
    File f = null;
    BufferedWriter writer = null;

    // write the contents to a temporary file
    try {
      f = File.createTempFile("temp", null);
      writer = new BufferedWriter(new FileWriter(f.getCanonicalPath()));
      writer.write(fileContents);

      return true;
    } catch (IOException ioe) {
      throw new AppException("flowHandling caught IO exception: " + ioe.getMessage());
    } finally {
      /*
       * SOLUTION: The return statement blocks the program flow so it needs to be removed.
       *           The larger problem is the close() call which can throw an exception that
       *           will not be caught and would be thrown by the flowHandling method.
       *
       *           The following lines are commented out and the close() method is surrounded
       *           by a try catch. It is should be tested for null in case the BufferedWriter
       *           was never opened above.
       *
       * writer.close();
       * return true;
       */
      if (writer != null) {
        try {
          writer.close();
        } catch (IOException ioe) {
          // this is an application error but does not represent an error for the user
          AppLogger.log("flowHandling failed to close writer: " + ioe.getMessage());
        }
      }
      // SOLUTION END
    }
  }

  /**
   * Project 3, Milestone 2, Task 3
   *
   * <p>TITLE: Throwing or catching RuntimeException
   *
   * <p>RISK: Runtime exception should not be thrown or caught since it represents a major
   * programmatic error. The generic Exception should not be caught or thrown either since the
   * reason for the error cannot be distinguished.
   *
   * <p>REF: CMU Software Engineering Institute ERR07-J
   *
   * @param query
   * @return String
   */
  /*
   * SOLUTION: Methods should not throw the all encompassing Exception. Instead a specific
   *           exception should be used.
   *
   *           The following line is commented out and replace with AppException:
   *
   * public String runtimeException(String cmd) throws Exception {
   */
  // SOLUTION END
  public String runtimeException(String cmd) throws AppException {
    try {
      // execute the OS command
      if (!Pattern.matches("[0-9A-Za-z]+", cmd)) {
        /*
         * SOLUTION: Application should never throw or catch Runtime exceptions.
         *           Only specific exceptions should be thrown since low level ones
         *           such as Runtime could flow back through the program in unexpected
         *           ways and present a security risk if controls are bypassed.
         *
         *           The following line is commented out and replaced:
         *
         * throw new RuntimeException("exec was passed a cmd with illegal characters");
         */
        throw new IOException("exec was passed a cmd with illegal characters");
        // SOLUTION END
      }

      // execute the requested command
      Runtime rt = Runtime.getRuntime();
      Process proc = rt.exec(new String[] {"sh", "-c", cmd + " "});
      int result = proc.waitFor();

      if (result != 0) {
        /*
         * SOLUTION: Same as above, dont throw runtime exceptions
         *
         * throw new RuntimeException("process error: " + result);
         */
        throw new IOException("process error: " + result);
        // SOLUTION ED
      }
      InputStream in = proc.getInputStream();

      // return the results of executing the command
      StringBuilder strBuilder = new StringBuilder();
      int i;

      while ((i = in.read()) != -1) {
        strBuilder.append((char) i);
      }

      return strBuilder.toString();
    }
    /**
     * SOLUTION: Do not catch runtime exception since it represents a major program error has
     * occurred
     *
     * <p>The following lines are commented out:
     *
     * <p>catch(RuntimeException re) { throw new Exception("exec caught runtime error: " +
     * re.getMessage()); }
     */
    catch (IOException ioe) {
      /*
       * SOLUTION: Change the exception thrown to AppException instead of the
       *           generic exception.
       *
       *           The following line is commented out and replaced:
       *
       * throw new Exception("exec caught IO error: " + ioe.getMessage());
       */
      throw new AppException("exec caught IO error: " + ioe.getMessage());
      // SOLUTION END
    } catch (InterruptedException ie) {
      /**
       * SOLUTION: Same error as above throwing Exception.
       *
       * <p>The following line is commented out and replaced:
       *
       * <p>throw new Exception("exec caught interupted error: " + ie.getMessage());
       */
      throw new AppException("exec caught interrupted error: " + ie.getMessage());
      // SOLUTION END
    }
  }

  /**
   * Project 3, Milestone 1, Task 4
   *
   * <p>TITLE: Handling NullPointerException
   *
   * <p>RISK: Accessing a null object represents a major programmatic error and can cause the
   * application to crash which results in a denial of service. Developers should not catch
   * NullPointerException; instead, objects which may be null should always be checked.
   *
   * <p>REF: CMU Software Engineering Institute ERR08-J
   *
   * @param query
   * @return String
   */
  /**
   * SOLUTION: Methods should never throw NullPointer Exception.
   *
   * <p>The line is commented out below and the more specific AppException is thrown
   *
   * <p>public boolean testNull(String str) throws NullPointerException { try {
   */
  public boolean testNull(String str) throws AppException {
    // SOLUTION END

    /**
     * SOLUTION: values should always be checked for null to avoid NullPointerException. NullPointer
     * should never be caught since it represents an major application error.
     *
     * <p>The str parameter should be tested for null before using the isEmpty() method
     */
    if (str == null) {
      throw new AppException("testNull was passed a null variable");
    }
    // SOLUTION END
    // check if str is empty
    return str.isEmpty();

    /**
     * SOLUTION: Comment out NullPointException since the variable is tested above and nothing
     * should throw the exception now.
     *
     * <p>}
     *
     * <p>catch(NullPointerException npe) { AppLogger.log("testNull caught NullPointer"); throw new
     * NullPointerException("testNull received null object"); }
     */
    // SOLUTION END
  }

  /**
   * Project 3, Milestone 3, Task 1
   *
   * <p>TITLE: Ignoring return values
   *
   * <p>RISK: Values returned by methods should not be ignored. The methods which return values
   * include String replacing or actions such as deleting a file. The return value should be
   * evaluated and errors handled even if they do not throw an exception.
   *
   * <p>REF: CMU Software Engineering Institute EXP00-J
   *
   * @param query
   * @return String
   */
  public String deleteFile(String fileName) throws AppException {
    if (fileName == null) {
      throw new AppException("deleteFile passed a null variable");
    }

    /**
     * SOLUTION: The replaceAll() method does not alter the existing string fileName but it returns
     * the a version of the String with the characters replaced. This represents a security issue
     * because the developer assumed the periods were replaced to avoid an injection attack such as
     * a dot dot (..).
     *
     * <p>The following line is commented out and replaced:
     *
     * <p>fileName.replaceAll("\\.", "_");
     */
    fileName = fileName.replaceAll("\\.", "_");
    // SOLUTION END
    File f = new File(fileName);

    try {
      /**
       * SOLUTION: The delete method returns a boolean of the success of the operation. The return
       * call is ignored and should be tested to stop execution flow. There are two ways to fix the
       * issue: use an if block to check the boolean of the file delete() call or use the
       * nio.file.Files.delete() method which throws an exception. The Files.delete() method will be
       * used as a replacement.
       *
       * <p>The following line is commented out:
       *
       * <p>f.delete();
       */
      Files.delete(f.toPath());
      // SOLUTION END

      return ("Deleted file: " + f.getCanonicalPath());
    } catch (IOException ioe) {
      throw new AppException("deleteFile caught IO exception: " + ioe.getMessage());
    }
  }

  /**
   * Project 3, Milestone 3, Task 2
   *
   * <p>TITLE: Avoiding null objects
   *
   * <p>RISK: Calling methods on null objects results in unstable application flow and will crash
   * programs. Object passed to methods or created should always be tested for null if there is a
   * chance the object does not result in a default value.
   *
   * <p>REF: CMU Software Engineering Institute EXP01-J and EXP54-J
   *
   * @param query
   * @return String
   */
  public String manipulateString(String str) throws AppException {
    // check if the value is null or empty before manipulating string
    /**
     * SOLUTION: The developer created an error by not understanding the difference between the
     * logical operation || and the bitwise comparison |. The logical version will short-circuit and
     * not execute further commands. While the bitwise comparison will execute all commands so even
     * if the test for null fails in the first part, the isEmpty() will still be executed on the
     * null str variable.
     *
     * <p>The following line is commented out and replace with the logical operator.
     *
     * <p>if(str == null | str.isEmpty() ) {
     */
    if (str == null || str.isEmpty()) {
      // SOLUTION END
      throw new AppException("manipulate string sent null or empty");
    }

    String manipulated = str.toUpperCase(Locale.ENGLISH);
    manipulated = manipulated.replaceAll("\\.", "_");

    return manipulated;
  }

  /**
   * Project 3, Milestone 3, Task 3
   *
   * <p>TITLE: Detect file-related errors
   *
   * <p>RISK: Some file handling methods report errors which are not thrown as exceptions.
   * Developers should understand these errors and account for them. The error could cause under
   * read/write of data or overflows which could result in an unstable application, crashes, or
   * other events which then cause security issues.
   *
   * <p>REF: CMU Software Engineering Institute FIO02-J
   *
   * @param query
   * @return String
   */
  public String detectFileError(String fileName) throws AppException {
    final int BUFFER = 1024;

    byte[] data = new byte[BUFFER];

    // read the first 1024 bytes of the file
    try (FileInputStream fis = new FileInputStream(fileName)) {
      /**
       * SOLUTION: The read() method returns the number of bytes read. The return should be check to
       * verify data was read.
       *
       * <p>The line is commented out below and wrapped in an if statement to verify data was read
       * into the byte array:
       *
       * <p>fix.read(data, 0, BUFFER) == 0) {
       */
      if (fis.read(data, 0, BUFFER) == 0) {
        throw new AppException("detectFileError read zero bytes");
      }
      // SOLUTION END

      // return the data from file read as a string
      // for this exercise, you can ignore checking if the data read is a valid
      // string or characters. we are only interested in file-related errors
      return Arrays.toString(data);
    } catch (FileNotFoundException fnfe) {
      throw new AppException("detectFileError could not find file: " + fnfe.getMessage());
    } catch (IOException ioe) {
      throw new AppException("detectFileError caught IO exception: " + ioe.getMessage());
    }
  }

  /**
   * Project 3, Milestone 3, Task 4
   *
   * <p>TITLE: Recover from an unstable state
   *
   * <p>RISK: Long running threads or other types of loop that may get stuck in a lock or continue
   * to consume resources and not exit gracefully. In the worst case, the unstable state may cause
   * the entire application to crash. In these specific cases, it is acceptable to catch the generic
   * Throwable which includes RuntimeException.
   *
   * <p>ADDITIONAL: The method to review is the recoverState(). The CheckSession runnable class is
   * only a helper. Focus on how to make the recoverState() able to exist gracefully if the possible
   * infinite loop in the Thread continues waiting for the session variable which never appears.
   *
   * <p>REF: CMU Software Engineering Institute ERR53-J, ERR08-J-EX0
   *
   * @param query
   * @return String
   */
  public void recoverState(String str) throws AppException {
    // create the thread to look for the data_id attribute in the session so we can
    // do further processing
    /*
     * SOLUTION: The previous example disallowed catching all exceptions, but one exception is
     *           allowed when the catch is used to check for specific errors, free resources,
     *           and re-throw. We need to surround the Thread in a try and catch Throwable.
     *
     *           The following line is commented out:
     *
     * Runnable checkSessionRunnable = new CheckSession(httpRequest.getSession());
     *
     * Thread t = new Thread(checkSessionRunnable);
     * t.start();
     */
    Runnable checkSessionRunnable = new CheckSession(httpRequest.getSession());
    Thread t = null;

    try {
      t = new Thread(checkSessionRunnable);

      t.start();
    } catch (Throwable throwable) {
      // at this point all memory resource may have been consumed but try to null the thread
      // and suggest Java perform Garbage collection
      t = null;
      System.gc(); // does not guarantee GC but only option
      AppLogger.log("recoverState exhausting resources and garbage collection attempted");
      throw new AppException("recoverState exahusted resources");
    }
    // SOLUTION END
  }

  /**
   * This class is part of Project 3, Milestone3, Task 4 NO CHANGES NEED TO BE PERFORMED ON THIS
   * CLASS
   */
  public static class CheckSession extends Thread {
    private HttpSession session = null;
    boolean found = false;
    int waitTime = 5000;

    public CheckSession(HttpSession session) {
      this.session = session;
    }

    @Override
    public synchronized void start() {
      Thread worker = new Thread(this);
      worker.start();
    }

    @Override
    public void run() {
      Object dataId = null;

      try {
        // loop until we see the data_id attribute in the session
        while (!found) {
          dataId = session.getAttribute("data_id");

          if (dataId instanceof String) {
            found = true;
          } else {
            Thread.sleep(waitTime);
          }
        }
      } catch (InterruptedException ie) {
        AppLogger.log("thread was interrupted: " + ie.getMessage());
        Thread.currentThread().interrupt();
      } catch (IllegalArgumentException iae) {
        AppLogger.log("thread caught illegal argumen to sleep: " + iae.getMessage());
      }
    }
  }

  /**
   * Project 3, Milestone 3, Task 5
   *
   * <p>TITLE: Handle open resources in cascading try-catch-finally
   *
   * <p>RISK: Multiple resources used with a finally block may not execute if one of the previous
   * methods fail. For example, if multiple Streams are opened within a try block and the finally
   * performs a close() one after the other, if any of the close() throws an exception, the flow
   * will exit and the finally close() statements with not execute. The failure to close resources
   * could leave an application in an unstable state.
   *
   * <p>REF: CMU Software Engineering Institute ERR54-J
   *
   * @param query
   * @return String
   */
  public boolean handleClose(String zipFile) throws AppException, IOException {
    /**
     * SOLUTION: All of the streams will be created in the code below, so they are commented out
     * here:
     *
     * <p>FileInputStream fis=null; ZipInputStream zis=null; FileOutputStream fos=null;
     * BufferedOutputStream dest=null;
     */
    // SOLUTION END

    final int BUFFER = 512;
    int count = 0;

    // create a path to the zipFile
    Path zipPath = null;
    try {
      zipPath = Paths.get("temp", "zip", "zipFile");
    } catch (InvalidPathException ipe) {
      throw new AppException("handleClose received an invalid zipFile path: " + ipe.getMessage());
    }

    byte[] data = null;

    try {
      /**
       * SOLUTION: The primary problem in the code is the close() methods in the finally block which
       * may not all execute if any throw an exception. There are 4 different streams opened so we
       * need a more reliable way. The issue can be fixed by wrapping each close in a try-catch
       * inside the finally block, or the better solution is to use try with resources.
       *
       * <p>The following lines are commented out and the streams opened in the try which lets Java
       * handle the auto close.
       *
       * <p>//open the zip file fis = new FileInputStream(zipFile); zis = new ZipInputStream(new
       * BufferedInputStream(fis));
       */
      try (FileInputStream fis = new FileInputStream(zipPath.toString())) {

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(fis))) {
          // SOLUTION END
          ZipEntry entry;

          /**
           * write the zip files
           *
           * <p>the code is simplified to reduce the size and does not take into account lessons
           * learned in other projects about avoiding zip bombs you do not need to fix that issue
           * here
           */
          while ((entry = zis.getNextEntry()) != null) {
            /**
             * SOLUTION: Same issue as above, wrap the opening of the streams in the try with
             * resources.
             *
             * <p>try { fos = new FileOutputStream(zipPath + entry.getName()); dest = new
             * BufferedOutputStream(fos);
             */
            try (FileOutputStream fos = new FileOutputStream(zipPath + entry.getName())) {
              try (BufferedOutputStream dest = new BufferedOutputStream(fos)) {

                while ((count = zis.read(data, 0, BUFFER)) != -1) {
                  dest.write(data, 0, count);
                }

                // clean up the zip entry
                dest.flush();
                zis.closeEntry();
              } // end dest
            } // end fos
            /**
             * SOLUTION: Remove the need for finally, so comment out the lines.
             *
             * <p>//clean up and close the resources finally { if(fos != null) { fos.close(); }
             * if(dest != null) { dest.close(); } }
             */
            // SOLUTION END
          }

          // zip extracted correctly with no errors
          return true;

          /** SOLUTION: Close the try statement added */
        } // end try ZipInputStream
      } // end try FileInputStream
      // SOLUTION END
    } catch (FileNotFoundException fnfe) {
      throw new AppException("zip file not found: " + fnfe.getMessage());
    }
    /**
     * SOLUTION: No longer need these closes, so code is commented out
     *
     * <p>//clean up the resources used to open the zip file finally { if(fis != null) {
     * fis.close(); } if(zis != null) { zis.close(); } }
     */
    // SOLUTION END
  }
}
