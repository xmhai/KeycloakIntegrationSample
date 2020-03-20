<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Register User</title>
</head>
<body>
<form:form action="${pageContext.request.contextPath}/updateProfile" method="POST">
  Update Profile<hr>
  Username: <input type="text" name="username" value="${username}" readonly><br>
  First name: <input type="text" name="firstName" value="${firstName}"><br>
  Last name: <input type="text" name="lastName" value="${lastName}"><br>
  Email: <input type="text" name="email" value="${email}"><br>
  <input type="submit" value="Submit">
</form:form>
</body>
</html>