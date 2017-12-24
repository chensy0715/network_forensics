package com.pcapanalyzer.bo;

import com.pcapanalyzer.utils.DataUtils;

public class PcapDataFrame {
	 //这个东西没啥卵用,不用关注
	
    /**
     * 目的 MAC 地址：6 byte
     */
	private byte[] desMac;
	
    /**
     * 源 MAC 地址：6 byte
     */
	private byte[] srcMac;
	
    /**
     * 数据帧类型:2 字节
     */
	private short frameType;

	public byte[] getDesMac() {
		return desMac;
	}

	public void setDesMac(byte[] desMac) {
		this.desMac = desMac;
	}

	public byte[] getSrcMac() {
		return srcMac;
	}

	public void setSrcMac(byte[] srcMac) {
		this.srcMac = srcMac;
	}

	public short getFrameType() {
		return frameType;
	}

	public void setFrameType(short frameType) {
		this.frameType = frameType;
	}
	
	public PcapDataFrame() {}
	
	@Override
	public String toString() {
		return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
	}
	
}
