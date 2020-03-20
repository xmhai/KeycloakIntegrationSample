package com.cl.stlucia.portal;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource, InitializingBean {

    protected FilterInvocationSecurityMetadataSource delegate;

    @Autowired
    protected SecurityExpressionHandler<FilterInvocation> expressionHandler;

    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return this.delegate.getAllConfigAttributes();
    }


    public Collection<ConfigAttribute> getAttributes(Object object) {
        return this.delegate.getAttributes(object);
    }


    public boolean supports(Class<?> clazz) {
        return this.delegate.supports(clazz);
    }


    @Override
    public void afterPropertiesSet() throws Exception {
    	Map<String, String> metadatas = new HashMap<String, String>();
    	metadatas.put("/", "permitAll");
    	metadatas.put("/home", "permitAll");
    	metadatas.put("/ssoLogin", "permitAll");
    	metadatas.put("/register", "permitAll");
    	metadatas.put("/logout", "permitAll");
    	metadatas.put("/**", "isAuthenticated()");
    	
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();
        for (Map.Entry me : metadatas.entrySet()) {
            requestMap.put(new AntPathRequestMatcher((String)me.getKey()), SecurityConfig.createList((String)me.getValue()));
        }
        
        this.delegate = new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, expressionHandler);
    }


    public void reset() throws Exception {
        afterPropertiesSet();
    }
}
