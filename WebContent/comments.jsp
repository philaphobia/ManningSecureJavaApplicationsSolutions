<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@page import="org.owasp.encoder.Encode"%>
<html>
<body>
	<H1>Comment verification for Johnson Autoparts</H1>
	<br>
	<form action="<%=request.getServletContext().getContextPath() %>/app" method='GET'>
	<table>
		<tr><td>Please verify your comment before submission:</td></tr>
		<% 
			String commentData = request.getParameter("param1");
			String safeComments="";
			
			//only work on data if it is not null
			if(commentData != null) {
				//encode for HTML first
				String safeHTML = Encode.forHtml(commentData);
				//encode for JavaScript after making HTML safe
				safeComments = Encode.forJavaScriptBlock(safeHTML);
			}
		%>
		<tr><td><textarea name='comment'><%= safeComments %></textarea>
		<tr><td><br/></td></tr>
			</table>
		<input type='hidden' name='project' value='project4'/>
		<input type='hidden' name='task' value='postComments'/>
		<input type='submit' name='Post Comment'/>
	</form>
</body>
</html>
