<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Internet Portal</title>
</head>
<body>
Welcome back: ${loginId}<br>
<a href="${pageContext.request.contextPath}/sso/logout">Logout</a><br>
<a href="${pageContext.request.contextPath}/ssoLogout">Logout (redirect)</a>
<hr>
User Functions<br>
<a href="${pageContext.request.contextPath}/updateProfile">Update Profile</a><br>
<a href="${pageContext.request.contextPath}/changePassword">Change Password</a><br>
<a href="${pageContext.request.contextPath}/ssoChangePassword">Change Password (redirect)</a>
<hr>
Administration Functions<br>
<a href="${pageContext.request.contextPath}/resetPassword">Reset Password</a><br>
<a href="${pageContext.request.contextPath}/unlockUser">UnLock User</a><br>
</body>
</html>