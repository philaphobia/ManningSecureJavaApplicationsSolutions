<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@page import="org.owasp.html.PolicyFactory"%>
<%@page import="org.owasp.html.HtmlPolicyBuilder" %>
<html>
<body>
	<H1>Blog verification for Johnson Autoparts</H1>
	<br>
	<form action="<%=request.getServletContext().getContextPath() %>/app" method='GET'>
	<table>
		<tr><td>Please verify your blog post before submission (some HTML allowed):</td></tr>
		<% 
			String blogData = request.getParameter("blog");
			String safeHTML="";
			
			//only work on data if it is not null
			if(blogData != null) {
				//use OWASP HTML sanitizer to limit elements to whitelist
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
		%>
		<tr><td><textarea name='param1'><%= safeHTML %></textarea>
		<tr><td><br/></td></tr>
			</table>
		<input type='hidden' name='project' value='project4'/>
		<input type='hidden' name='task' value='postBlog'/>
		<input type='submit' name='Blog'/>
	</form>
</body>
</html>
