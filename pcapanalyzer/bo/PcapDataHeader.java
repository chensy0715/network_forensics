package com.pcapanalyzer.bo;

import com.pcapanalyzer.utils.DataUtils;

public class PcapDataHeader {
	//这个是数据头,也就是说有多少个这个就有多少个数据包
	
    /**
     * 时间戳（秒）：记录数据包抓获的时间
     *
     */
	private int timeS;
	
	
    /**
     * 时间戳（微秒）：抓取数据包时的微秒值（4个字节）
     */
	private int timeMs;
	
	
    /**
     * 数据包长度：标识所抓获的数据包保存在 pcap 文件中的实际长度，以字节为单位（4个字节）
     */
	private int caplen;
	
	
    /**
     * 数据包实际长度： 所抓获的数据包的真实长度（4个字节）
     * 如果文件中保存不是完整的数据包，那么这个值可能要比前面的数据包长度的值大。
     */
	private int len;						
	
	public int getTimeS() {
		return timeS;
	}

	public void setTimeS(int timeS) {
		this.timeS = timeS;
	}

	public int getTimeMs() {
		return timeMs;
	}

	public void setTimeMs(int timeMs) {
		this.timeMs = timeMs;
	}

	public int getCaplen() {
		return caplen;
	}

	public void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	public int getLen() {
		return len;
	}

	public void setLen(int len) {
		this.len = len;
	}

	public PcapDataHeader() {}
	
	@Override
	public String toString() {
		return "PcapDataHeader [timeS=" +  DataUtils.intToHexString(timeS)
				+ ", timeMs=" +  DataUtils.intToHexString(timeMs)
				+ ", caplen=" +  caplen
				+ ", len=" +  len
				+ "]";
	}

}