package com.pcapanalyzer.bo;

import com.pcapanalyzer.utils.DataUtils;


public class UDPHeader {
	//这就是udp头的部分了
	
	private short srcPort;			// 源端口
	private short dstPort;			// 目的端口
	private short length;			// 数据包长
	private short checkSum;		// 校验和
	
	public short getSrcPort() {
		return srcPort;
	}
	public void setSrcPort(short srcPort) {
		this.srcPort = srcPort;
	}
	public short getDstPort() {
		return dstPort;
	}
	public void setDstPort(short dstPort) {
		this.dstPort = dstPort;
	}
	public short getLength() {
		return length;
	}
	public void setLength(short length) {
		this.length = length;
	}
	public short getCheckSum() {
		return checkSum;
	}
	public void setCheckSum(short checkSum) {
		this.checkSum = checkSum;
	}
	
	public UDPHeader() {}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "UDPHeader [srcPort=" + srcPort
				+ ", dstPort=" + dstPort
				+ ", length=" + length
				+ ", checkSum=" + DataUtils.shortToHexString(checkSum)
				+ "]";
	}
	
}
