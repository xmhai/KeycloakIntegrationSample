<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Unlock User</title>
</head>
<body>
<form:form action="${pageContext.request.contextPath}/unlockUser" method="POST">
  Unlock User<hr>
  Username: <input type="text" name="username"><br>
  <input type="submit" value="Submit">
</form:form>
</body>
</html>
