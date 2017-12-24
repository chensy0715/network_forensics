package com.pcapanalyzer.bo;

import java.util.List;


public class PcapStruct {
	//这个是就就是pcap文件的结构,也就是一个pcap文件头和很多数据头,具体你可以去看图示

	private PcapFileHeader fileHeader;
	private List<PcapDataHeader> dataHeaders;
	
	public PcapFileHeader getFileHeader() {
		return fileHeader;
	}
	public void setFileHeader(PcapFileHeader fileHeader) {
		this.fileHeader = fileHeader;
	}
	public List<PcapDataHeader> getDataHeaders() {
		return dataHeaders;
	}
	public void setDataHeaders(List<PcapDataHeader> dataHeaders) {
		this.dataHeaders = dataHeaders;
	}
	
	public PcapStruct() {}
	
	
}
