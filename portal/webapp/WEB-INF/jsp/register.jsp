<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Register User</title>
</head>
<body>
<form:form action="${pageContext.request.contextPath}/register" method="POST">
  User Rigistration<hr>
  Username: <input type="text" name="username"><br>
  First name: <input type="text" name="firstName"><br>
  Last name: <input type="text" name="lastName"><br>
  Email: <input type="text" name="email"><br>
  <input type="submit" value="Submit">
</form:form>
</body>
</html>