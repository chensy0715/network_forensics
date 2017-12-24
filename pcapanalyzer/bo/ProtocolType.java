package com.pcapanalyzer.bo;

public enum ProtocolType {
	
	OTHER("0"), 	//这个是个enum,枚举,就是列一些常用的常量			
	TCP("6"), 					
	UDP("17");					
	
	private String type;
	
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	private ProtocolType(String type) {
		this.type = type;
	}
	
}
