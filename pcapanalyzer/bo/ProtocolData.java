package com.pcapanalyzer.bo;


public class ProtocolData {
	//这个东西就是用来区分不同的tcp连接的,一个tco连接中有很多包,而且tcp连接是双向的,所以我重写这个类的hashcode方法和equals方法

	String srcIP;    //这个是源ip										
	String desIP;	//这个是目标ip									
	
	String srcPort;		//这个是	源端口						
	String desPort;		//这个是目标端口								
	
	ProtocolType protocolType = ProtocolType.OTHER;  //默认既不是tcp也不是udp,等到判断的时候再加上		

	public String getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(String srcIP) {
		this.srcIP = srcIP;
	}

	public String getDesIP() {
		return desIP;
	}

	public void setDesIP(String desIP) {
		this.desIP = desIP;
	}

	public String getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(String srcPort) {
		this.srcPort = srcPort;
	}

	public String getDesPort() {
		return desPort;
	}

	public void setDesPort(String desPort) {
		this.desPort = desPort;
	}

	public ProtocolType getProtocolType() {
		return protocolType;
	}

	public void setProtocolType(ProtocolType protocolType) {
		this.protocolType = protocolType;
	}

	public ProtocolData() {
		
	}

	public ProtocolData(String srcIP, String desIP, String srcPort,
			String desPort, ProtocolType protocolType) {
		this.srcIP = srcIP;
		this.desIP = desIP;
		this.srcPort = srcPort;
		this.desPort = desPort;
		this.protocolType = protocolType;
	}

	@Override
	public String toString() {
		return "ProtocolData [srcIP=" + srcIP
				+ ", desIP=" + desIP
				+ ", srcPort=" + srcPort
				+ ", desPort=" + desPort
				+ ", protocolType=" + protocolType
				+ "]";
	}
	@Override  
    public int hashCode() {  
        return 6*srcIP.hashCode()+6*desIP.hashCode()+12*srcPort.hashCode()+12*desPort.hashCode();  
    }  
	@Override
	public boolean equals(Object obj) {
		ProtocolData pro = (ProtocolData)obj;	
		if(pro.desIP.equals(desIP)&&pro.desPort.equals(desPort)&&pro.srcIP.equals(srcIP)&&pro.srcPort.equals(srcPort)) {
			return true;
		}
		if(pro.desIP.equals(srcIP)&&pro.desPort.equals(srcPort)&&pro.srcIP.equals(desIP)&&pro.srcPort.equals(desPort)) {
			return true;
		}
		return false;
	}
}
