package com.pcapanalyzer.bo;

public class TcpDataPacket {
	//这个类主要定义了一个tcp包的结构
	
	//这个是每个tcp包的数据头
	private PcapDataHeader pcapDataHeader;
	//这个是每个tcp包的ip头
	private IPHeader ipheader;
	//这个是每个tcp包的数据头
	private TCPHeader tcpheader;
	
	private String content;
	public TcpDataPacket(IPHeader ipheader,TCPHeader tcpheader,PcapDataHeader pcapDataHeader,String content) {
		this.ipheader=ipheader;
		this.tcpheader=tcpheader;
		this.pcapDataHeader=pcapDataHeader;
		this.content=content;
	}
	public IPHeader getIpheader() {
		return ipheader;
	}
	public void setIpheader(IPHeader ipheader) {
		this.ipheader = ipheader;
	}
	public TCPHeader getTcpheader() {
		return tcpheader;
	}
	public void setTcpheader(TCPHeader tcpheader) {
		this.tcpheader = tcpheader;
	}
	public PcapDataHeader getPcapDataHeader() {
		return pcapDataHeader;
	}
	public void setPcapDataHeader(PcapDataHeader pcapDataHeader) {
		this.pcapDataHeader = pcapDataHeader;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
 
 
}
