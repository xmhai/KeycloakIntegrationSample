package com.cl.stlucia.portal;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

public class MyFilterInvocationServiceSecurityMetadataSourceBeanPostProcessor implements BeanPostProcessor {
	private FilterInvocationSecurityMetadataSource metadataSource;

	public void setMetadataSource(FilterInvocationSecurityMetadataSource metadataSource) {
		this.metadataSource = metadataSource;
	}

	public Object postProcessBeforeInitialization(Object bean, String beanName) {
		if (bean instanceof FilterInvocationSecurityMetadataSource) {
			return metadataSource;
		}
		return bean;
	}

	public Object postProcessAfterInitialization(Object bean, String beanName) {
		return bean;
	}
}