<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@page import="org.owasp.html.PolicyFactory"%>
<%@page import="org.owasp.html.HtmlPolicyBuilder" %>
<%
	/**
	 * Project 4, Milestone 1, Task 5
	 * 
	 * TITLE: Sanitize HTML when tags are needed
	 * 
	 * RISK: If the application allows untrusted data to include HTML, then an accept list tags
	 *       should be enforced. Denying will not help and the tags allowed should be very limited
	 *       to avoid tricky malicious users from bypassing the expected controls.
	 * 
	 * REF: OWASP XSS Cheat Sheet Rule #6
	 *      https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
	 * 
	 * IMPORTANT: For the following task you will be working this JSP postBlog() method in Project4:
	 *            
	 *            Since blog.jsp is taking a parameter and displaying it to the user, the data must be
	 *            sanitized. The data is then sent to postBlog() method and should be sanitized again
	 *            before processing.
	 *            
	 *            For this JSP, imagine the user sent the following as the blog parameter:
	 *            close the real text area</textarea><script>alert('XSS from closed TextArea');</script><textarea>new text
	 *            
	 *            Notice how the textarea tag is closed, then JavaScript is entered, and the textarea
	 *            is then closed. This creates a valid HTML with two textareas and JavaScript tags in
	 *            the middle which executes in the target users browser.
	 *            
	 *            A hint is provided in the import statements above
	 */
%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<body>
	<H1>Blog verification for Johnson Autoparts</H1>
	<br>
	<form action="<%=request.getServletContext().getContextPath() %>/app" method='GET'>
	<table>
		<tr><td>Please verify your blog post before submission (HTML tags P,TABLE,DIV,TR,TD allowed):</td></tr>
		<%
		/**
	 	 * SOLUTION: Instead of putting the blog parameter directly back into the HTML we need to perform
	 	 *           sanitization. Unlike other times where we can use regex to remove characters or
	 	 *           sanitize characters that could be bad, sometimes HTML is allowed. In these cases,
	 	 *           the best solution is to leverage a proven library. As the imports suggest, we will
	 	 *           use the OWASP HTML Sanitizer to create a policy of the allowed HTML tags. The
	 	 *           content will then be filtered to only allow the accepted tags before placing
	 	 *           the data into the browser.
	 	 */
		%>
		<% 
		    //get the untrusted data from the request
			String blogData = request.getParameter("blog");
			String safeHTML="";
			
			//only work on data if it is not null
			if(blogData != null) {
				//use OWASP HTML sanitizer to limit elements to accept 
				PolicyFactory policy = new HtmlPolicyBuilder()
					.allowElements("p")
			   	 	.allowElements("table")
			   	 	.allowElements("div")
			   	 	.allowElements("tr")
			   		.allowElements("td")
			   	 	.toFactory();
				
				//apply policy to the HTML
				safeHTML = policy.sanitize(blogData);
			}
			
			//include the sanitized safeHTML data in the text area
		%>
		<tr><td><textarea name='param1'><%= safeHTML %></textarea>
		<tr><td><br/></td></tr>
			</table>
		<input type='hidden' name='project' value='project4'/>
		<input type='hidden' name='task' value='postBlog'/>
		<input type='submit' name='Blog'/>
	</form>
        <script src="/SecureCoding/csrfguard"></script>
</body>
</html>
