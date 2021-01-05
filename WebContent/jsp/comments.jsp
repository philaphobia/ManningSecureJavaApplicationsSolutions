<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@page import="org.owasp.encoder.Encode"%>
<% 	
/**
 * Project 4, Milestone 1, Task 2
 * 
 * TITLE: Encoding data and escaping output for display
 * 
 * RISK: Untrusted data must not be included in the web browser since it may contain unsafe code.
 *       In a more complex attack, a malicious user may include JavaScript and HTML. types of attacks.
 *       Untrusted data displayed to the user should neutralize JavaScript and HTML. Use the OWASP
 *       Enocder protect to filter both.
 * 
 * REF: CMU Software Engineering Institute IDS14-J
 * 
 * IMPORTANT: The encoding is applicable in Java as well if you are returning data which needs to
 *            be encoded. This JSP form takes data from the param1 variable and displays it to the user
 *            as a confirmation before final submission.
 *
 *            A hint is provided with the import statement above
 */ 
 %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<body>
	<H1>Comment verification for Johnson Autoparts</H1>
	<br>
	<form action="<%=request.getServletContext().getContextPath() %>/app" method='GET'>
	<table>
		<tr><td>Please verify your comment before submission:</td></tr>
		<% 
		    /**
		     * SOLUTION: Instead of using the GET paramater without filtering we need to
		     *           use the Encoder twice. OWASP Encoder project recommends sanitizing
		     *           for HTML first and then performing a second pass to sanitize
		     *           JavaScript
		     */
			String commentParam = request.getParameter("comments");
			String safeComments="";
			
			//only work on data if it is not null
			if(commentParam != null) {
				//encode for HTML first
				String safeHTML = Encode.forHtml(commentParam);
				//encode for JavaScript after making HTML safe
				safeComments = Encode.forJavaScriptBlock(safeHTML);
			}
		%>
		<tr><td><textarea name='comment'><%= safeComments %></textarea>
		<%
		     /**
		      * SOLUTION: The original data is replace with our sanitized safeComments data
		      */
		%>
		<tr><td><br/></td></tr>
			</table>
		<input type='hidden' name='project' value='project4'/>
		<input type='hidden' name='task' value='postComments'/>
		<input type='submit' name='Post Comment'/>
	</form>
	<%
	/**
	 * SOLUTION: Instead of relying on the untrusted header information, we can implement CSRF
	 *           token which is generate by the first request and sent with the form post which
	 *           is then validate by the SecurityFilter
	 */
	%>
	<script src="/SecureCoding/csrfguard"></script>
	<%
	//SOLUTION END
	%>
</body>
</html>
