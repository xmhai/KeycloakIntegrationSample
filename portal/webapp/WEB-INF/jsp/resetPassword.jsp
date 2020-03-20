<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Change Password</title>
</head>
<body>
<form:form action="${pageContext.request.contextPath}/resetPassword" method="POST">
  Reset Password<hr>
  Username: <input type="text" name="username"><br>
  New Password: <input type="text" name="newPassword"><br>
  <input type="submit" value="Submit">
</form:form>
</body>
</html>
